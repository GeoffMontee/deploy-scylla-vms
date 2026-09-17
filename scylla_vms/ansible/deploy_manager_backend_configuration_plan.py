"""Immutable deploy-only Manager backend-configuration context and plan.

This subprocess-free owner validates the complete Manager-activation prefix and
records only the decisions that current canonical design evidence can support.
The design selects the official recommended local one-node backend while its
package, storage, tuning, configuration, schema, source, and recovery contracts
remain explicitly unresolved and blocked.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from scylla_vms.ansible.deploy_manager_activation_plan import (
    ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION,
    DeployManagerActivationBoundaryStatus,
    DeployManagerActivationContextStore,
    DeployManagerActivationPlanStore,
    DeployManagerActivationSourceState,
    StoredDeployManagerActivationContext,
)
from scylla_vms.ansible.deploy_manager_activation_plan import (
    _build_context_record as _build_activation_context_record,
)
from scylla_vms.ansible.deploy_manager_activation_plan import (
    _build_plan_record as _build_activation_plan_record,
)
from scylla_vms.ansible.deploy_manager_activation_plan import (
    _build_plan_steps as _build_activation_plan_steps,
)
from scylla_vms.ansible.deploy_manager_activation_plan import (
    _load_planning_context as _load_activation_planning_context,
)
from scylla_vms.ansible.deploy_manager_activation_plan import (
    _validate_contracts as _validate_activation_contracts,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.deploy_scylla_post_bootstrap_reconciliation import (
    ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION,
    DeployPostBootstrapArtifactState,
    DeployPostBootstrapReconciliationStore,
    StoredDeployPostBootstrapReconciliation,
    reconcile_deploy_scylla_post_bootstrap,
)
from scylla_vms.ansible.registry import PLAYBOOK_NAMES, get_playbook
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
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

ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_GATE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-configuration-gate/v2"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_INTENT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-configuration-intent/v2"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-configuration-context/v2"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-configuration-plan-step/v2"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-configuration-plan/v2"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-configuration-plan-report/v2"
)
MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION = (
    "deploy-scylla-vms.manager-backend-local-one-node-policy/v1"
)
DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-configuration-context.json"
)
DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-configuration-plan.json"
)

_OPERATION = "deploy"
_STAGE = "manager-backend-configuration"
_BOUNDARY = "manager-backend-configuration"
_ACTIVATION_BOUNDARY = "backend-configure"
_ORIGINAL_MAPPING_COUNT = 21
_SECRET_SOURCE_POLICY = "environment-only"
_SECRET_SOURCE_STATE = "not-collected"
_CONFIGURATION_STATE = "not-performed"
_AUTHORIZATION_STATE = "unavailable"
_EXECUTION_STATE = "unavailable"
_PUBLIC_WORKFLOW_STATE = "unavailable"
_NEXT_IMPLEMENTATION_CONTRACT = "manager-backend-preflight-orchestration-contract"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_BACKEND_SOURCE_NAMES = frozenset(
    {
        "manager-backend",
        "manager-backend-configure",
        "manager-backend-configuration",
    }
)


class DeployManagerBackendConfigurationArtifactState(StrEnum):
    """Immutable context/plan persistence result."""

    CREATED = "created"
    REUSED = "reused"


class DeployManagerBackendConfigurationGateState(StrEnum):
    """Closed planning state for one prerequisite."""

    PASSED = "passed"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class DeployManagerBackendConfigurationDecisionState(StrEnum):
    """Whether canonical design evidence approves one backend decision."""

    APPROVED = "approved"
    UNKNOWN = "unknown"


class DeployManagerBackendMode(StrEnum):
    """The reviewed Manager backend topology."""

    LOCAL_ONE_NODE = "local-one-node"


class DeployManagerBackendConfigurationSourceState(StrEnum):
    """Whether an exact reviewed backend source is packaged."""

    AVAILABLE = "source-available"
    UNAVAILABLE = "source-unavailable"


class DeployManagerBackendConfigurationPlanStatus(StrEnum):
    """Planning result before authorization or execution."""

    BLOCKED = "blocked"


_GATE_DEFINITIONS: tuple[
    tuple[
        str,
        DeployManagerBackendConfigurationGateState,
        str | None,
    ],
    ...,
] = (
    (
        "canonical-provenance",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "manager-target-identity",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "manager-install-evidence",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "manager-service-inactive-masked",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "scylla-final-health",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "scylla-topology",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "secret-source-policy",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "source-catalog-provenance",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "backend-mode",
        DeployManagerBackendConfigurationGateState.PASSED,
        None,
    ),
    (
        "backend-package-availability",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-package-availability-unknown",
    ),
    (
        "backend-storage-suitability",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-storage-suitability-unknown",
    ),
    (
        "backend-tuning-suitability",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-tuning-suitability-unknown",
    ),
    (
        "backend-identity",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-identity-unknown",
    ),
    (
        "backend-topology",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-topology-unknown",
    ),
    (
        "backend-capacity",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-capacity-unknown",
    ),
    (
        "backend-health",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-health-unknown",
    ),
    (
        "authentication",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-authentication-unapproved",
    ),
    (
        "tls",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-tls-unapproved",
    ),
    (
        "secret-source-binding",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-secret-source-unbound",
    ),
    (
        "schema-bootstrap",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-schema-bootstrap-unapproved",
    ),
    (
        "setup-behavior",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-setup-behavior-unapproved",
    ),
    (
        "contact-point",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-contact-point-unapproved",
    ),
    (
        "port",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-port-unapproved",
    ),
    (
        "configuration-ownership",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-configuration-ownership-unapproved",
    ),
    (
        "configuration-mode",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-configuration-mode-unapproved",
    ),
    (
        "source-contract",
        DeployManagerBackendConfigurationGateState.BLOCKED,
        "manager-backend-configuration-source-unavailable",
    ),
    (
        "recovery-semantics",
        DeployManagerBackendConfigurationGateState.UNKNOWN,
        "manager-backend-recovery-semantics-unapproved",
    ),
)


@dataclass(frozen=True, slots=True)
class ManagerBackendLocalOneNodePolicy:
    """Versioned, value-free safety policy for the selected local backend."""

    backend_mode: DeployManagerBackendMode
    target_role: str
    managed_data_cluster_backend: str
    cql_network_ingress: str
    contact_scope: str
    cql_port: int
    scylla_release: str
    backend_credentials: str
    backend_tls: str
    manager_service_state: str
    package_installation: str
    configuration_write: str
    setup_execution: str
    schema_creation: str
    local_scylla_service_start: str
    manager_service_start: str
    manager_agent_token_policy: str
    policy_digest: str
    schema_version: str = MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION
            or self.backend_mode is not DeployManagerBackendMode.LOCAL_ONE_NODE
            or self.target_role != "manager"
            or self.managed_data_cluster_backend != "forbidden"
            or self.cql_network_ingress != "forbidden"
            or self.contact_scope != "loopback-only"
            or self.cql_port != 9042
            or self.scylla_release != "2026.2"
            or self.backend_credentials != "not-required"
            or self.backend_tls != "not-required"
            or self.manager_service_state != "masked-inactive"
            or any(
                state != "not-performed"
                for state in (
                    self.package_installation,
                    self.configuration_write,
                    self.setup_execution,
                    self.schema_creation,
                    self.local_scylla_service_start,
                    self.manager_service_start,
                )
            )
            or self.manager_agent_token_policy != "environment-only-required"
            or self.policy_digest != _digest_record(self, "policy_digest")
        ):
            raise StatePersistenceError(
                "Manager local one-node backend policy conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> ManagerBackendLocalOneNodePolicy:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager local one-node backend policy",
        )
        try:
            return cls(
                backend_mode=DeployManagerBackendMode(
                    require_string(value, "backend_mode")
                ),
                target_role=require_string(value, "target_role"),
                managed_data_cluster_backend=require_string(
                    value, "managed_data_cluster_backend"
                ),
                cql_network_ingress=require_string(value, "cql_network_ingress"),
                contact_scope=require_string(value, "contact_scope"),
                cql_port=_integer(value["cql_port"], "cql_port"),
                scylla_release=require_string(value, "scylla_release"),
                backend_credentials=require_string(value, "backend_credentials"),
                backend_tls=require_string(value, "backend_tls"),
                manager_service_state=require_string(value, "manager_service_state"),
                package_installation=require_string(value, "package_installation"),
                configuration_write=require_string(value, "configuration_write"),
                setup_execution=require_string(value, "setup_execution"),
                schema_creation=require_string(value, "schema_creation"),
                local_scylla_service_start=require_string(
                    value, "local_scylla_service_start"
                ),
                manager_service_start=require_string(value, "manager_service_start"),
                manager_agent_token_policy=require_string(
                    value, "manager_agent_token_policy"
                ),
                policy_digest=require_string(value, "policy_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Manager local one-node backend policy enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendConfigurationGate:
    """One value-free prerequisite gate."""

    name: str
    state: DeployManagerBackendConfigurationGateState
    evidence_digest: str | None
    blocker: str | None
    gate_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_GATE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        definitions = {
            name: (state, blocker) for name, state, blocker in _GATE_DEFINITIONS
        }
        expected = definitions.get(self.name)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_GATE_SCHEMA_VERSION
            or expected is None
            or (self.state, self.blocker) != expected
            or (
                self.evidence_digest is None
                if self.state is DeployManagerBackendConfigurationGateState.PASSED
                else False
            )
            or (
                self.evidence_digest is not None
                if self.state is DeployManagerBackendConfigurationGateState.UNKNOWN
                else False
            )
            or self.gate_digest != _digest_record(self, "gate_digest")
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration gate conflicts"
            )
        if self.evidence_digest is not None:
            validate_digest(
                self.evidence_digest,
                "deploy Manager backend configuration gate evidence digest",
            )
        if self.blocker is not None and _BLOCKER.fullmatch(self.blocker) is None:
            raise StatePersistenceError(
                "deploy Manager backend configuration blocker is invalid"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendConfigurationGate:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend configuration gate",
        )
        evidence = value["evidence_digest"]
        blocker = value["blocker"]
        if evidence is not None and not isinstance(evidence, str):
            raise StatePersistenceError(
                "deploy Manager backend configuration gate evidence is invalid"
            )
        if blocker is not None and not isinstance(blocker, str):
            raise StatePersistenceError(
                "deploy Manager backend configuration gate blocker is invalid"
            )
        try:
            return cls(
                name=require_string(value, "name"),
                state=DeployManagerBackendConfigurationGateState(
                    require_string(value, "state")
                ),
                evidence_digest=evidence,
                blocker=blocker,
                gate_digest=require_string(value, "gate_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend configuration gate state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendConfigurationIntent:
    """Selected backend topology plus unresolved implementation decisions."""

    classification: OperationClassification
    backend_mode: DeployManagerBackendConfigurationDecisionState
    backend_mode_value: DeployManagerBackendMode
    backend_policy: ManagerBackendLocalOneNodePolicy
    backend_identity: DeployManagerBackendConfigurationDecisionState
    backend_topology: DeployManagerBackendConfigurationDecisionState
    backend_capacity: DeployManagerBackendConfigurationDecisionState
    backend_health: DeployManagerBackendConfigurationDecisionState
    authentication: DeployManagerBackendConfigurationDecisionState
    tls: DeployManagerBackendConfigurationDecisionState
    schema_bootstrap: DeployManagerBackendConfigurationDecisionState
    contact_point: DeployManagerBackendConfigurationDecisionState
    port: DeployManagerBackendConfigurationDecisionState
    configuration_ownership: DeployManagerBackendConfigurationDecisionState
    configuration_mode: DeployManagerBackendConfigurationDecisionState
    recovery_semantics: DeployManagerBackendConfigurationDecisionState
    secret_source_policy: str
    secret_source_policy_digest: str
    secret_source_state: str
    source_state: DeployManagerBackendConfigurationSourceState
    source_digest: str | None
    configuration_state: str
    intent_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_INTENT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        decisions = (
            self.backend_identity,
            self.backend_topology,
            self.backend_capacity,
            self.backend_health,
            self.authentication,
            self.tls,
            self.schema_bootstrap,
            self.contact_point,
            self.port,
            self.configuration_ownership,
            self.configuration_mode,
            self.recovery_semantics,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_INTENT_SCHEMA_VERSION
            or self.classification is not OperationClassification.MUTATING
            or self.backend_mode
            is not DeployManagerBackendConfigurationDecisionState.APPROVED
            or self.backend_mode_value is not DeployManagerBackendMode.LOCAL_ONE_NODE
            or self.backend_policy.backend_mode is not self.backend_mode_value
            or any(
                item is not DeployManagerBackendConfigurationDecisionState.UNKNOWN
                for item in decisions
            )
            or self.secret_source_policy != _SECRET_SOURCE_POLICY
            or self.secret_source_state != _SECRET_SOURCE_STATE
            or self.source_state
            is not DeployManagerBackendConfigurationSourceState.UNAVAILABLE
            or self.source_digest is not None
            or self.configuration_state != _CONFIGURATION_STATE
            or self.intent_digest != _digest_record(self, "intent_digest")
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration intent conflicts"
            )
        validate_digest(
            self.secret_source_policy_digest,
            "deploy Manager backend secret-source policy digest",
        )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendConfigurationIntent:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend configuration intent",
        )
        source_digest = value["source_digest"]
        if source_digest is not None and not isinstance(source_digest, str):
            raise StatePersistenceError(
                "deploy Manager backend configuration source digest is invalid"
            )
        decision_fields = {
            "backend_mode",
            "backend_identity",
            "backend_topology",
            "backend_capacity",
            "backend_health",
            "authentication",
            "tls",
            "schema_bootstrap",
            "contact_point",
            "port",
            "configuration_ownership",
            "configuration_mode",
            "recovery_semantics",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                if name in decision_fields:
                    parsed[name] = DeployManagerBackendConfigurationDecisionState(
                        require_string(value, name)
                    )
                elif name == "backend_mode_value":
                    parsed[name] = DeployManagerBackendMode(require_string(value, name))
                elif name == "backend_policy":
                    parsed[name] = ManagerBackendLocalOneNodePolicy.from_object(
                        _mapping(value[name], name)
                    )
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "source_state":
                    parsed[name] = DeployManagerBackendConfigurationSourceState(
                        require_string(value, name)
                    )
                elif name == "source_digest":
                    parsed[name] = source_digest
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend configuration intent enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendConfigurationContext:
    """Immutable complete provenance and value-free backend intent."""

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
    activation_context_artifact_digest: str
    activation_context_record_digest: str
    activation_plan_artifact_digest: str
    activation_plan_digest: str
    activation_backend_step_digest: str
    post_targets_artifact_digest: str
    post_targets_record_digest: str
    post_bootstrap_artifact_digest: str
    post_bootstrap_record_digest: str
    final_health_evidence_digest: str
    final_health_reconciliation_digest: str
    current_member_count: int
    current_member_set_digest: str
    metadata_generation: int
    metadata_artifact_digest: str
    desired_spec_digest: str
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
    ansible_source_version: str
    ansible_source_digest: str
    manager_target_id: str
    manager_target_digest: str
    manager_agent_target_ids: tuple[str, ...]
    manager_agent_target_count: int
    manager_agent_target_set_digest: str
    topology_digest: str
    identity_provenance_digest: str
    manager_server_evidence_artifact_digest: str
    manager_server_evidence_digest: str
    manager_server_provenance_digest: str
    manager_agent_evidence_artifact_digest: str
    manager_agent_evidence_set_digest: str
    manager_agent_provenance_set_digest: str
    manager_package_provenance_digest: str
    manager_service_masked: bool
    manager_service_inactive: bool
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    secret_source_policy_digest: str
    intent: DeployManagerBackendConfigurationIntent
    gates: tuple[DeployManagerBackendConfigurationGate, ...]
    gate_count: int
    passed_gate_count: int
    unknown_gate_count: int
    blocked_gate_count: int
    gate_set_digest: str
    blockers: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    status: DeployManagerBackendConfigurationPlanStatus
    next_implementation_contract: str
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    record_digest: str
    activation_context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
    )
    activation_plan_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
    )
    post_bootstrap_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = {
            state: sum(gate.state is state for gate in self.gates)
            for state in DeployManagerBackendConfigurationGateState
        }
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION
            or self.activation_context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
            or self.activation_plan_schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
            or self.post_bootstrap_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.current_member_count != self.manager_agent_target_count
            or self.current_member_set_digest != self.manager_agent_target_set_digest
            or _LOGICAL_ID.fullmatch(self.manager_target_id) is None
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or not self.manager_agent_target_ids
            or self.manager_agent_target_ids
            != tuple(sorted(set(self.manager_agent_target_ids)))
            or any(
                _LOGICAL_ID.fullmatch(item) is None
                for item in self.manager_agent_target_ids
            )
            or self.manager_agent_target_count != len(self.manager_agent_target_ids)
            or self.manager_agent_target_set_digest
            != _digest_object(list(self.manager_agent_target_ids))
            or not self.manager_service_masked
            or not self.manager_service_inactive
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or not self.original_mapping_unchanged
            or tuple(gate.name for gate in self.gates)
            != tuple(item[0] for item in _GATE_DEFINITIONS)
            or self.gate_count != len(self.gates)
            or self.passed_gate_count
            != counts[DeployManagerBackendConfigurationGateState.PASSED]
            or self.unknown_gate_count
            != counts[DeployManagerBackendConfigurationGateState.UNKNOWN]
            or self.blocked_gate_count
            != counts[DeployManagerBackendConfigurationGateState.BLOCKED]
            or self.gate_set_digest
            != _digest_object([gate.to_object() for gate in self.gates])
            or self.blockers
            != tuple(sorted(gate.blocker for gate in self.gates if gate.blocker))
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.status is not DeployManagerBackendConfigurationPlanStatus.BLOCKED
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.authorization_state != _AUTHORIZATION_STATE
            or self.execution_state != _EXECUTION_STATE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_STATE
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.secret_source_policy_digest
            != self.intent.secret_source_policy_digest
            or self.record_digest != _digest_record(self, "record_digest")
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration context conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.current_member_count,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.manager_agent_target_count,
            self.gate_count,
            self.passed_gate_count,
            self.blocker_count,
        ):
            _positive_integer(
                count, "deploy Manager backend configuration generation or count"
            )
        if self.unknown_gate_count < 1 or self.blocked_gate_count < 1:
            raise StatePersistenceError(
                "deploy Manager backend configuration unresolved gate count conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager backend configuration digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendConfigurationContext:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend configuration context",
        )
        integers = {
            "generation",
            "journal_generation",
            "current_member_count",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "manager_agent_target_count",
            "original_mapping_count",
            "gate_count",
            "passed_gate_count",
            "unknown_gate_count",
            "blocked_gate_count",
            "blocker_count",
        }
        booleans = {
            "manager_service_masked",
            "manager_service_inactive",
            "original_mapping_unchanged",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name in booleans:
                    parsed[name] = _boolean(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "status":
                    parsed[name] = DeployManagerBackendConfigurationPlanStatus(
                        require_string(value, name)
                    )
                elif name in {"manager_agent_target_ids", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                elif name == "intent":
                    parsed[name] = DeployManagerBackendConfigurationIntent.from_object(
                        _mapping(item, name)
                    )
                elif name == "gates":
                    parsed[name] = tuple(
                        DeployManagerBackendConfigurationGate.from_object(
                            _mapping(gate, "backend configuration gate")
                        )
                        for gate in _array(item, name)
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend configuration context enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendConfigurationContext:
    record: DeployManagerBackendConfigurationContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class DeployManagerBackendConfigurationPlanStep:
    """The sole ordered backend-configuration boundary."""

    sequence: int
    boundary: str
    classification: OperationClassification
    target_ids: tuple[str, ...]
    target_count: int
    target_set_digest: str
    activation_step_digest: str
    intent_digest: str
    gate_set_digest: str
    source_state: DeployManagerBackendConfigurationSourceState
    source_digest: str | None
    authorization_requirement: str
    performance_state: str
    status: DeployManagerBackendConfigurationPlanStatus
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_STEP_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_STEP_SCHEMA_VERSION
            or self.sequence != 1
            or self.boundary != _BOUNDARY
            or self.classification is not OperationClassification.MUTATING
            or len(self.target_ids) != 1
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or self.target_count != 1
            or self.target_set_digest != _digest_object(list(self.target_ids))
            or self.source_state
            is not DeployManagerBackendConfigurationSourceState.UNAVAILABLE
            or self.source_digest is not None
            or self.authorization_requirement != "blocked-before-authorization"
            or self.performance_state != _CONFIGURATION_STATE
            or self.status is not DeployManagerBackendConfigurationPlanStatus.BLOCKED
            or self.blockers != tuple(sorted(set(self.blockers)))
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _digest_record(self, "step_digest")
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration plan step conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager backend configuration step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendConfigurationPlanStep:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend configuration plan step",
        )
        source_digest = value["source_digest"]
        if source_digest is not None and not isinstance(source_digest, str):
            raise StatePersistenceError(
                "deploy Manager backend configuration step source is invalid"
            )
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                boundary=require_string(value, "boundary"),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                target_ids=_string_tuple(value["target_ids"], "target_ids"),
                target_count=_integer(value["target_count"], "target_count"),
                target_set_digest=require_string(value, "target_set_digest"),
                activation_step_digest=require_string(value, "activation_step_digest"),
                intent_digest=require_string(value, "intent_digest"),
                gate_set_digest=require_string(value, "gate_set_digest"),
                source_state=DeployManagerBackendConfigurationSourceState(
                    require_string(value, "source_state")
                ),
                source_digest=source_digest,
                authorization_requirement=require_string(
                    value, "authorization_requirement"
                ),
                performance_state=require_string(value, "performance_state"),
                status=DeployManagerBackendConfigurationPlanStatus(
                    require_string(value, "status")
                ),
                blockers=_string_tuple(value["blockers"], "blockers"),
                blocker_digest=require_string(value, "blocker_digest"),
                step_digest=require_string(value, "step_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend configuration plan step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendConfigurationPlan:
    """Immutable blocked plan for one distinct backend boundary."""

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
    activation_plan_artifact_digest: str
    activation_plan_digest: str
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    manager_target_id: str
    manager_target_digest: str
    steps: tuple[DeployManagerBackendConfigurationPlanStep, ...]
    step_count: int
    passed_gate_count: int
    unknown_gate_count: int
    blocked_gate_count: int
    source_available_count: int
    source_unavailable_count: int
    authorization_available_count: int
    not_performed_count: int
    blocked_count: int
    blocker_digest: str
    next_implementation_contract: str
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    plan_digest: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION
    )
    activation_plan_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION
            or self.activation_plan_schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or not self.original_mapping_unchanged
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or self.step_count != 1
            or len(self.steps) != 1
            or self.steps[0].target_ids != (self.manager_target_id,)
            or self.source_available_count != 0
            or self.source_unavailable_count != 1
            or self.authorization_available_count != 0
            or self.not_performed_count != 1
            or self.blocked_count != 1
            or self.blocker_digest != self.steps[0].blocker_digest
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.authorization_state != _AUTHORIZATION_STATE
            or self.execution_state != _EXECUTION_STATE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_STATE
            or self.plan_digest != _digest_record(self, "plan_digest")
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration plan conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.step_count,
            self.passed_gate_count,
            self.not_performed_count,
            self.source_unavailable_count,
            self.blocked_count,
        ):
            _positive_integer(count, "deploy Manager backend plan count")
        if self.unknown_gate_count < 1 or self.blocked_gate_count < 1:
            raise StatePersistenceError(
                "deploy Manager backend plan unresolved gate count conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager backend configuration plan digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendConfigurationPlan:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend configuration plan",
        )
        integers = {
            "generation",
            "journal_generation",
            "original_mapping_count",
            "step_count",
            "passed_gate_count",
            "unknown_gate_count",
            "blocked_gate_count",
            "source_available_count",
            "source_unavailable_count",
            "authorization_available_count",
            "not_performed_count",
            "blocked_count",
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
                        DeployManagerBackendConfigurationPlanStep.from_object(
                            _mapping(step, "backend configuration plan step")
                        )
                        for step in _array(item, name)
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend configuration plan enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendConfigurationPlan:
    record: DeployManagerBackendConfigurationPlan
    artifact_digest: str


class DeployManagerBackendConfigurationContextStore:
    """Owner-only immutable backend context store."""

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
        self._path = deploy_manager_backend_configuration_context_path(
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
    ) -> StoredDeployManagerBackendConfigurationContext:
        value, digest = self._file.read()
        record = DeployManagerBackendConfigurationContext.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration context identity conflicts"
            )
        return StoredDeployManagerBackendConfigurationContext(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendConfigurationContext:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendConfigurationContext,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendConfigurationContext,
        DeployManagerBackendConfigurationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend configuration context operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager backend configuration context is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployManagerBackendConfigurationArtifactState.REUSED,
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendConfigurationContext(record, digest),
            DeployManagerBackendConfigurationArtifactState.CREATED,
        )


class DeployManagerBackendConfigurationPlanStore:
    """Owner-only immutable backend plan store."""

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
        self._path = deploy_manager_backend_configuration_plan_path(paths, operation_id)
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
    ) -> StoredDeployManagerBackendConfigurationPlan:
        value, digest = self._file.read()
        record = DeployManagerBackendConfigurationPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration plan identity conflicts"
            )
        return StoredDeployManagerBackendConfigurationPlan(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendConfigurationPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendConfigurationPlan,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendConfigurationPlan,
        DeployManagerBackendConfigurationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend configuration plan operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager backend configuration plan is immutable; "
                    "use a new operation"
                )
            return current, DeployManagerBackendConfigurationArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendConfigurationPlan(record, digest),
            DeployManagerBackendConfigurationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendConfigurationPlanReport:
    """Bounded redacted projection of the blocked plan."""

    operation_id: uuid.UUID
    context_state: DeployManagerBackendConfigurationArtifactState
    plan_state: DeployManagerBackendConfigurationArtifactState
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_digest: str
    manager_target_id: str
    manager_target_digest: str
    manager_agent_target_ids: tuple[str, ...]
    manager_agent_target_count: int
    manager_agent_target_set_digest: str
    classification: OperationClassification
    status: DeployManagerBackendConfigurationPlanStatus
    gate_count: int
    passed_gate_count: int
    unknown_gate_count: int
    blocked_gate_count: int
    blocker_count: int
    blocker_digest: str
    source_state: DeployManagerBackendConfigurationSourceState
    secret_source_policy_digest: str
    secret_source_state: str
    original_mapping_unchanged: bool
    next_implementation_contract: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION
    )
    plan_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_REPORT_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION
            or self.manager_agent_target_count != len(self.manager_agent_target_ids)
            or self.classification is not OperationClassification.MUTATING
            or self.status is not DeployManagerBackendConfigurationPlanStatus.BLOCKED
            or self.gate_count
            != self.passed_gate_count
            + self.unknown_gate_count
            + self.blocked_gate_count
            or self.passed_gate_count < 1
            or self.unknown_gate_count < 1
            or self.blocked_gate_count < 1
            or self.blocker_count != self.unknown_gate_count + self.blocked_gate_count
            or self.source_state
            is not DeployManagerBackendConfigurationSourceState.UNAVAILABLE
            or self.secret_source_state != _SECRET_SOURCE_STATE
            or not self.original_mapping_unchanged
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _AUTHORIZATION_STATE
            or self.execution_state != _EXECUTION_STATE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_STATE
        ):
            raise StatePersistenceError(
                "deploy Manager backend configuration report conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager backend report digest")

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
            "boundary": {
                "classification": self.classification.value,
                "source_state": self.source_state.value,
                "status": self.status.value,
            },
            "gates": {
                "blocked_count": self.blocked_gate_count,
                "blocker_count": self.blocker_count,
                "blocker_digest": self.blocker_digest,
                "count": self.gate_count,
                "passed_count": self.passed_gate_count,
                "unknown_count": self.unknown_gate_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "manager_scope": {
                "agent_target_count": self.manager_agent_target_count,
                "agent_target_ids": list(self.manager_agent_target_ids),
                "agent_target_set_digest": self.manager_agent_target_set_digest,
                "server_target_digest": self.manager_target_digest,
                "server_target_id": self.manager_target_id,
            },
            "next_implementation_contract": self.next_implementation_contract,
            "operation_id": str(self.operation_id),
            "original_mapping_unchanged": self.original_mapping_unchanged,
            "schema_version": self.schema_version,
            "secret_source": {
                "policy_digest": self.secret_source_policy_digest,
                "state": self.secret_source_state,
            },
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
                "public_workflow": self.public_workflow_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _PlanningContext:
    activation: StoredDeployManagerActivationContext
    activation_plan_artifact_digest: str
    activation_plan_digest: str
    activation_backend_step_digest: str
    post_bootstrap: StoredDeployPostBootstrapReconciliation
    intent: DeployManagerBackendConfigurationIntent
    gates: tuple[DeployManagerBackendConfigurationGate, ...]


def plan_deploy_manager_backend_configuration(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerBackendConfigurationPlanReport:
    """Persist or reuse the blocked backend context and plan."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _validate_contracts()
    _refuse_ambiguous_artifacts(paths, operation_id)

    context_store = DeployManagerBackendConfigurationContextStore(paths, operation_id)
    plan_store = DeployManagerBackendConfigurationPlanStore(paths, operation_id)
    for path in (context_store.path, plan_store.path):
        validate_state_file(path, allow_missing=True)
    if plan_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "deploy Manager backend configuration plan exists without its context"
        )

    loaded = _load_planning_context(paths, operation_id, lock=lock)
    activation = loaded.activation.record
    existing_context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=activation.cluster_uuid,
            expected_cluster_name=activation.cluster_name,
        )
        if context_store.path.exists()
        else None
    )
    existing_plan = (
        plan_store.read_locked(
            lock,
            expected_cluster_uuid=activation.cluster_uuid,
            expected_cluster_name=activation.cluster_name,
        )
        if plan_store.path.exists()
        else None
    )
    created_at = (
        existing_context.record.created_at
        if existing_context is not None
        else format_timestamp(datetime.now(UTC))
    )
    context_record = _build_context_record(loaded, created_at=created_at)
    expected_context_digest = digest_bytes(serialize_json(context_record.to_object()))
    context_for_plan = StoredDeployManagerBackendConfigurationContext(
        context_record, expected_context_digest
    )
    step = _build_plan_step(context_record)
    plan_record = _build_plan_record(
        context_for_plan,
        step=step,
        created_at=(
            existing_plan.record.created_at if existing_plan is not None else created_at
        ),
    )

    stored_context, context_state = context_store.write_locked(
        context_record, lock=lock
    )
    if stored_context.artifact_digest != expected_context_digest:
        raise StateConflictError(
            "deploy Manager backend configuration context bytes changed"
        )
    stored_plan, plan_state = plan_store.write_locked(plan_record, lock=lock)
    return _build_report(
        stored_context,
        stored_plan,
        context_state=context_state,
        plan_state=plan_state,
    )


def deploy_manager_backend_configuration_context_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend configuration context path is not canonical"
        )
    return path


def deploy_manager_backend_configuration_plan_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend configuration plan path is not canonical"
        )
    return path


def deploy_manager_backend_configuration_context_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_FILENAME_SUFFIX
    )


def deploy_manager_backend_configuration_plan_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_FILENAME_SUFFIX
    )


def _load_planning_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _PlanningContext:
    activation_context_store = DeployManagerActivationContextStore(paths, operation_id)
    activation_plan_store = DeployManagerActivationPlanStore(paths, operation_id)
    for path in (activation_context_store.path, activation_plan_store.path):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "deploy Manager backend configuration requires the exact "
                "Manager activation context and plan"
            )

    _validate_activation_contracts()
    current = _load_activation_planning_context(paths, operation_id, lock=lock)
    cluster_uuid = current.post_targets.record.cluster_uuid
    cluster_name = current.post_targets.record.cluster_name
    activation = activation_context_store.read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    activation_plan = activation_plan_store.read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    expected_activation = _build_activation_context_record(
        current, created_at=activation.record.created_at
    )
    expected_activation_digest = digest_bytes(
        serialize_json(expected_activation.to_object())
    )
    expected_activation_plan = _build_activation_plan_record(
        StoredDeployManagerActivationContext(
            expected_activation, expected_activation_digest
        ),
        steps=_build_activation_plan_steps(expected_activation),
        created_at=activation_plan.record.created_at,
    )
    if (
        activation.record != expected_activation
        or activation.artifact_digest != expected_activation_digest
        or activation_plan.record != expected_activation_plan
        or activation.record.post_targets_artifact_digest
        != current.post_targets.artifact_digest
        or activation.record.post_targets_record_digest
        != current.post_targets.record.record_digest
    ):
        raise StateConflictError(
            "deploy Manager backend configuration activation provenance drifted"
        )

    bridge_report = reconcile_deploy_scylla_post_bootstrap(
        state_root=paths.state_root,
        cluster_name=cluster_name,
        operation_id=operation_id,
        lock=lock,
    )
    if bridge_report.artifact_state is not DeployPostBootstrapArtifactState.REUSED:
        raise StateConflictError(
            "deploy Manager backend configuration requires a prior immutable "
            "post-bootstrap reconciliation"
        )
    post_bootstrap = DeployPostBootstrapReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    activation_steps = activation_plan.record.steps
    backend_steps = tuple(
        step for step in activation_steps if step.boundary == _ACTIVATION_BOUNDARY
    )
    if (
        len(backend_steps) != 1
        or backend_steps[0].sequence != 1
        or backend_steps[0].classification is not OperationClassification.MUTATING
        or backend_steps[0].target_ids != (activation.record.manager_target_id,)
        or backend_steps[0].source_state
        is not DeployManagerActivationSourceState.UNAVAILABLE
        or backend_steps[0].source_digest is not None
        or backend_steps[0].status is not DeployManagerActivationBoundaryStatus.BLOCKED
        or post_bootstrap.record.current_member_set_digest
        != activation.record.manager_agent_target_set_digest
        or post_bootstrap.record.current_member_count
        != activation.record.manager_agent_target_count
        or post_bootstrap.record.original_mapping_digest
        != activation.record.original_mapping_digest
        or post_bootstrap.record.final_health_evidence_digest
        != post_bootstrap.record.mapped_health_evidence_digest
        or post_bootstrap.record.catalog_digest != activation.record.catalog_digest
        or post_bootstrap.record.ansible_source_digest
        != activation.record.ansible_source_digest
    ):
        raise StateConflictError(
            "deploy Manager backend configuration activation, health, or "
            "mapping provenance conflicts"
        )

    intent = _build_intent()
    gates = _build_gates(activation.record, post_bootstrap, intent)
    return _PlanningContext(
        activation,
        activation_plan.artifact_digest,
        activation_plan.record.plan_digest,
        backend_steps[0].step_digest,
        post_bootstrap,
        intent,
        gates,
    )


def _build_local_one_node_policy() -> ManagerBackendLocalOneNodePolicy:
    values: dict[str, object] = {
        "backend_mode": DeployManagerBackendMode.LOCAL_ONE_NODE,
        "target_role": "manager",
        "managed_data_cluster_backend": "forbidden",
        "cql_network_ingress": "forbidden",
        "contact_scope": "loopback-only",
        "cql_port": 9042,
        "scylla_release": "2026.2",
        "backend_credentials": "not-required",
        "backend_tls": "not-required",
        "manager_service_state": "masked-inactive",
        "package_installation": "not-performed",
        "configuration_write": "not-performed",
        "setup_execution": "not-performed",
        "schema_creation": "not-performed",
        "local_scylla_service_start": "not-performed",
        "manager_service_start": "not-performed",
        "manager_agent_token_policy": "environment-only-required",
        "policy_digest": "",
    }
    values["policy_digest"] = _digest_values(
        ManagerBackendLocalOneNodePolicy, values, "policy_digest"
    )
    return ManagerBackendLocalOneNodePolicy(**values)  # type: ignore[arg-type]


def _build_intent() -> DeployManagerBackendConfigurationIntent:
    policy_digest = _digest_object(
        {
            "intake": _SECRET_SOURCE_POLICY,
            "persistence": "forbidden",
            "state": _SECRET_SOURCE_STATE,
        }
    )
    backend_policy = _build_local_one_node_policy()
    values: dict[str, object] = {
        "classification": OperationClassification.MUTATING,
        "backend_mode": DeployManagerBackendConfigurationDecisionState.APPROVED,
        "backend_mode_value": DeployManagerBackendMode.LOCAL_ONE_NODE,
        "backend_policy": backend_policy,
        "backend_identity": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "backend_topology": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "backend_capacity": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "backend_health": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "authentication": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "tls": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "schema_bootstrap": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "contact_point": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "port": DeployManagerBackendConfigurationDecisionState.UNKNOWN,
        "configuration_ownership": (
            DeployManagerBackendConfigurationDecisionState.UNKNOWN
        ),
        "configuration_mode": (DeployManagerBackendConfigurationDecisionState.UNKNOWN),
        "recovery_semantics": (DeployManagerBackendConfigurationDecisionState.UNKNOWN),
        "secret_source_policy": _SECRET_SOURCE_POLICY,
        "secret_source_policy_digest": policy_digest,
        "secret_source_state": _SECRET_SOURCE_STATE,
        "source_state": DeployManagerBackendConfigurationSourceState.UNAVAILABLE,
        "source_digest": None,
        "configuration_state": _CONFIGURATION_STATE,
        "intent_digest": "",
    }
    values["intent_digest"] = _digest_values(
        DeployManagerBackendConfigurationIntent, values, "intent_digest"
    )
    return DeployManagerBackendConfigurationIntent(**values)  # type: ignore[arg-type]


def _build_gates(
    activation: Any,
    post_bootstrap: StoredDeployPostBootstrapReconciliation,
    intent: DeployManagerBackendConfigurationIntent,
) -> tuple[DeployManagerBackendConfigurationGate, ...]:
    bridge = post_bootstrap.record
    evidence = {
        "canonical-provenance": _digest_object(
            {
                "desired": activation.desired_spec_digest,
                "inventory": activation.inventory_artifact_digest,
                "observation": activation.observation_artifact_digest,
                "readiness": activation.readiness_artifact_digest,
                "trust": activation.trust_artifact_digest,
            }
        ),
        "manager-target-identity": activation.identity_provenance_digest,
        "manager-install-evidence": activation.manager_package_provenance_digest,
        "manager-service-inactive-masked": _digest_object(
            {
                "evidence": activation.manager_server_evidence_digest,
                "inactive": True,
                "masked": True,
            }
        ),
        "scylla-final-health": bridge.final_health_evidence_digest,
        "scylla-topology": activation.topology_digest,
        "secret-source-policy": intent.secret_source_policy_digest,
        "source-catalog-provenance": _digest_object(
            {
                "catalog": activation.catalog_digest,
                "source": activation.ansible_source_digest,
            }
        ),
        "backend-mode": intent.backend_policy.policy_digest,
        "source-contract": activation.ansible_source_digest,
    }
    result: list[DeployManagerBackendConfigurationGate] = []
    for name, state, blocker in _GATE_DEFINITIONS:
        values: dict[str, object] = {
            "name": name,
            "state": state,
            "evidence_digest": evidence.get(name),
            "blocker": blocker,
            "gate_digest": "",
        }
        values["gate_digest"] = _digest_values(
            DeployManagerBackendConfigurationGate, values, "gate_digest"
        )
        result.append(DeployManagerBackendConfigurationGate(**values))  # type: ignore[arg-type]
    return tuple(result)


def _build_context_record(
    context: _PlanningContext,
    *,
    created_at: str,
) -> DeployManagerBackendConfigurationContext:
    activation = context.activation.record
    bridge = context.post_bootstrap.record
    blockers = tuple(
        sorted(gate.blocker for gate in context.gates if gate.blocker is not None)
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": activation.cluster_uuid,
        "cluster_name": activation.cluster_name,
        "operation_id": activation.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": activation.request_digest,
        "journal_generation": activation.journal_generation,
        "journal_digest": activation.journal_digest,
        "journal_status": activation.journal_status,
        "journal_phase": activation.journal_phase,
        "activation_context_artifact_digest": context.activation.artifact_digest,
        "activation_context_record_digest": activation.record_digest,
        "activation_plan_artifact_digest": context.activation_plan_artifact_digest,
        "activation_plan_digest": context.activation_plan_digest,
        "activation_backend_step_digest": context.activation_backend_step_digest,
        "post_targets_artifact_digest": activation.post_targets_artifact_digest,
        "post_targets_record_digest": activation.post_targets_record_digest,
        "post_bootstrap_artifact_digest": context.post_bootstrap.artifact_digest,
        "post_bootstrap_record_digest": bridge.record_digest,
        "final_health_evidence_digest": bridge.final_health_evidence_digest,
        "final_health_reconciliation_digest": (
            bridge.final_health_reconciliation_digest
        ),
        "current_member_count": bridge.current_member_count,
        "current_member_set_digest": bridge.current_member_set_digest,
        "metadata_generation": activation.metadata_generation,
        "metadata_artifact_digest": activation.metadata_artifact_digest,
        "desired_spec_digest": activation.desired_spec_digest,
        "observation_generation": activation.observation_generation,
        "observation_artifact_digest": activation.observation_artifact_digest,
        "observation_manifest_digest": activation.observation_manifest_digest,
        "inventory_generation": activation.inventory_generation,
        "inventory_artifact_digest": activation.inventory_artifact_digest,
        "inventory_digest": activation.inventory_digest,
        "trust_generation": activation.trust_generation,
        "trust_artifact_digest": activation.trust_artifact_digest,
        "trust_entries_digest": activation.trust_entries_digest,
        "readiness_artifact_digest": activation.readiness_artifact_digest,
        "readiness_record_digest": activation.readiness_record_digest,
        "catalog_digest": activation.catalog_digest,
        "ansible_source_version": activation.ansible_source_version,
        "ansible_source_digest": activation.ansible_source_digest,
        "manager_target_id": activation.manager_target_id,
        "manager_target_digest": activation.manager_target_digest,
        "manager_agent_target_ids": activation.manager_agent_target_ids,
        "manager_agent_target_count": activation.manager_agent_target_count,
        "manager_agent_target_set_digest": activation.manager_agent_target_set_digest,
        "topology_digest": activation.topology_digest,
        "identity_provenance_digest": activation.identity_provenance_digest,
        "manager_server_evidence_artifact_digest": (
            activation.manager_server_evidence_artifact_digest
        ),
        "manager_server_evidence_digest": (activation.manager_server_evidence_digest),
        "manager_server_provenance_digest": (
            activation.manager_server_provenance_digest
        ),
        "manager_agent_evidence_artifact_digest": (
            activation.manager_agent_evidence_artifact_digest
        ),
        "manager_agent_evidence_set_digest": (
            activation.manager_agent_evidence_set_digest
        ),
        "manager_agent_provenance_set_digest": (
            activation.manager_agent_provenance_set_digest
        ),
        "manager_package_provenance_digest": (
            activation.manager_package_provenance_digest
        ),
        "manager_service_masked": True,
        "manager_service_inactive": True,
        "original_mapping_count": activation.original_mapping_count,
        "original_mapping_digest": activation.original_mapping_digest,
        "original_mapping_unchanged": activation.original_mapping_unchanged,
        "secret_source_policy_digest": context.intent.secret_source_policy_digest,
        "intent": context.intent,
        "gates": context.gates,
        "gate_count": len(context.gates),
        "passed_gate_count": sum(
            gate.state is DeployManagerBackendConfigurationGateState.PASSED
            for gate in context.gates
        ),
        "unknown_gate_count": sum(
            gate.state is DeployManagerBackendConfigurationGateState.UNKNOWN
            for gate in context.gates
        ),
        "blocked_gate_count": sum(
            gate.state is DeployManagerBackendConfigurationGateState.BLOCKED
            for gate in context.gates
        ),
        "gate_set_digest": _digest_object([gate.to_object() for gate in context.gates]),
        "blockers": blockers,
        "blocker_count": len(blockers),
        "blocker_digest": _digest_object(list(blockers)),
        "status": DeployManagerBackendConfigurationPlanStatus.BLOCKED,
        "next_implementation_contract": _NEXT_IMPLEMENTATION_CONTRACT,
        "authorization_state": _AUTHORIZATION_STATE,
        "execution_state": _EXECUTION_STATE,
        "public_workflow_state": _PUBLIC_WORKFLOW_STATE,
        "record_digest": "",
    }
    values["record_digest"] = _digest_values(
        DeployManagerBackendConfigurationContext, values, "record_digest"
    )
    return DeployManagerBackendConfigurationContext(**values)  # type: ignore[arg-type]


def _build_plan_step(
    context: DeployManagerBackendConfigurationContext,
) -> DeployManagerBackendConfigurationPlanStep:
    values: dict[str, object] = {
        "sequence": 1,
        "boundary": _BOUNDARY,
        "classification": OperationClassification.MUTATING,
        "target_ids": (context.manager_target_id,),
        "target_count": 1,
        "target_set_digest": context.manager_target_digest,
        "activation_step_digest": context.activation_backend_step_digest,
        "intent_digest": context.intent.intent_digest,
        "gate_set_digest": context.gate_set_digest,
        "source_state": DeployManagerBackendConfigurationSourceState.UNAVAILABLE,
        "source_digest": None,
        "authorization_requirement": "blocked-before-authorization",
        "performance_state": _CONFIGURATION_STATE,
        "status": DeployManagerBackendConfigurationPlanStatus.BLOCKED,
        "blockers": context.blockers,
        "blocker_digest": context.blocker_digest,
        "step_digest": "",
    }
    values["step_digest"] = _digest_values(
        DeployManagerBackendConfigurationPlanStep, values, "step_digest"
    )
    return DeployManagerBackendConfigurationPlanStep(**values)  # type: ignore[arg-type]


def _build_plan_record(
    context: StoredDeployManagerBackendConfigurationContext,
    *,
    step: DeployManagerBackendConfigurationPlanStep,
    created_at: str,
) -> DeployManagerBackendConfigurationPlan:
    record = context.record
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
        "activation_plan_artifact_digest": record.activation_plan_artifact_digest,
        "activation_plan_digest": record.activation_plan_digest,
        "original_mapping_count": record.original_mapping_count,
        "original_mapping_digest": record.original_mapping_digest,
        "original_mapping_unchanged": record.original_mapping_unchanged,
        "manager_target_id": record.manager_target_id,
        "manager_target_digest": record.manager_target_digest,
        "steps": (step,),
        "step_count": 1,
        "passed_gate_count": record.passed_gate_count,
        "unknown_gate_count": record.unknown_gate_count,
        "blocked_gate_count": record.blocked_gate_count,
        "source_available_count": 0,
        "source_unavailable_count": 1,
        "authorization_available_count": 0,
        "not_performed_count": 1,
        "blocked_count": 1,
        "blocker_digest": record.blocker_digest,
        "next_implementation_contract": record.next_implementation_contract,
        "authorization_state": record.authorization_state,
        "execution_state": record.execution_state,
        "public_workflow_state": record.public_workflow_state,
        "plan_digest": "",
    }
    values["plan_digest"] = _digest_values(
        DeployManagerBackendConfigurationPlan, values, "plan_digest"
    )
    return DeployManagerBackendConfigurationPlan(**values)  # type: ignore[arg-type]


def _build_report(
    context: StoredDeployManagerBackendConfigurationContext,
    plan: StoredDeployManagerBackendConfigurationPlan,
    *,
    context_state: DeployManagerBackendConfigurationArtifactState,
    plan_state: DeployManagerBackendConfigurationArtifactState,
) -> DeployManagerBackendConfigurationPlanReport:
    record = context.record
    return DeployManagerBackendConfigurationPlanReport(
        operation_id=record.operation_id,
        context_state=context_state,
        plan_state=plan_state,
        context_artifact_digest=context.artifact_digest,
        context_record_digest=record.record_digest,
        plan_artifact_digest=plan.artifact_digest,
        plan_digest=plan.record.plan_digest,
        manager_target_id=record.manager_target_id,
        manager_target_digest=record.manager_target_digest,
        manager_agent_target_ids=record.manager_agent_target_ids,
        manager_agent_target_count=record.manager_agent_target_count,
        manager_agent_target_set_digest=record.manager_agent_target_set_digest,
        classification=record.intent.classification,
        status=record.status,
        gate_count=record.gate_count,
        passed_gate_count=record.passed_gate_count,
        unknown_gate_count=record.unknown_gate_count,
        blocked_gate_count=record.blocked_gate_count,
        blocker_count=record.blocker_count,
        blocker_digest=record.blocker_digest,
        source_state=record.intent.source_state,
        secret_source_policy_digest=record.secret_source_policy_digest,
        secret_source_state=record.intent.secret_source_state,
        original_mapping_unchanged=record.original_mapping_unchanged,
        next_implementation_contract=record.next_implementation_contract,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        authorization_state=record.authorization_state,
        execution_state=record.execution_state,
        public_workflow_state=record.public_workflow_state,
    )


def _validate_contracts() -> None:
    server = get_playbook("manager-server")
    tasks = get_playbook("manager-tasks")
    if (
        _BACKEND_SOURCE_NAMES.intersection(PLAYBOOK_NAMES)
        or not server.source_available
        or not tasks.source_available
        or server.classification is not OperationClassification.MUTATING
        or tasks.classification is not OperationClassification.SENSITIVE
    ):
        raise StateConflictError(
            "deploy Manager backend configuration source or catalog contract drifted"
        )


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    exact = {
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_FILENAME_SUFFIX}",
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_FILENAME_SUFFIX}",
    }
    prefix = f"{operation_id}.ansible-deploy-manager-backend-configuration-"
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Manager backend configuration history"
        ) from error
    for entry in entries:
        if entry.name in exact:
            continue
        if entry.name.startswith(prefix) or (
            "manager-backend-configuration-context" in entry.name
            or "manager-backend-configuration-plan" in entry.name
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Manager backend configuration refuses ambiguous or later "
                "artifacts"
            )


def _dataclass_object(value: object) -> dict[str, object]:
    if not is_dataclass(value):
        raise StatePersistenceError("backend configuration record is not a dataclass")
    return {
        field.name: _serialize_value(getattr(value, field.name))
        for field in fields(cast(Any, value))
    }


def _serialize_value(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if is_dataclass(value):
        return _dataclass_object(value)
    if isinstance(value, tuple):
        return [_serialize_value(item) for item in value]
    return value


def _digest_record(value: object, digest_field: str) -> str:
    result = _dataclass_object(value)
    result[digest_field] = ""
    return _digest_object(result)


def _digest_values(
    data_type: type[Any],
    values: Mapping[str, object],
    digest_field: str,
) -> str:
    result: dict[str, object] = {}
    for field in fields(data_type):
        result[field.name] = _serialize_value(values.get(field.name, field.default))
    result[digest_field] = ""
    return _digest_object(result)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Manager backend configuration paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Manager backend configuration planning requires the matching "
            "held deploy lock"
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
        cast(str, getattr(value, field.name))
        for field in fields(cast(Any, value))
        if field.name.endswith("_digest")
        and isinstance(getattr(value, field.name), str)
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
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_GATE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_INTENT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_STEP_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_FILENAME_SUFFIX",
    "DeployManagerBackendConfigurationArtifactState",
    "DeployManagerBackendConfigurationContext",
    "DeployManagerBackendConfigurationContextStore",
    "DeployManagerBackendConfigurationDecisionState",
    "DeployManagerBackendConfigurationGate",
    "DeployManagerBackendConfigurationGateState",
    "DeployManagerBackendConfigurationIntent",
    "DeployManagerBackendConfigurationPlan",
    "DeployManagerBackendConfigurationPlanReport",
    "DeployManagerBackendConfigurationPlanStatus",
    "DeployManagerBackendConfigurationPlanStep",
    "DeployManagerBackendConfigurationPlanStore",
    "DeployManagerBackendConfigurationSourceState",
    "StoredDeployManagerBackendConfigurationContext",
    "StoredDeployManagerBackendConfigurationPlan",
    "deploy_manager_backend_configuration_context_id_from_filename",
    "deploy_manager_backend_configuration_context_path",
    "deploy_manager_backend_configuration_plan_id_from_filename",
    "deploy_manager_backend_configuration_plan_path",
    "plan_deploy_manager_backend_configuration",
]
