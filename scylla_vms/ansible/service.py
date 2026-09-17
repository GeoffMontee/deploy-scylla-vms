"""Lock-, inventory-, trust-, and version-gated Ansible execution service."""

import base64
import binascii
import json
import os
import re
import uuid
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from scylla_vms.ansible.commands import AnsibleCommand, AnsibleCommandBuilder
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    InventoryListMachineEvidence,
    ReadinessReport,
    build_readiness_report,
    validate_inventory_list_output,
    validate_inventory_machine_output,
)
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.toolchain import (
    AnsibleToolchain,
    parse_ansible_core_version,
)
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StatePersistenceError,
    ToolExecutionError,
    ToolPrerequisiteError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadata
from scylla_vms.process import ProcessResult, ProcessSpec
from scylla_vms.state import StatePaths, validate_state_file

if TYPE_CHECKING:
    from scylla_vms.ansible.base_os import BaseOsEvidence
    from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
        StoredDeployManagerBackendConfigurationContext,
        StoredDeployManagerBackendConfigurationPlan,
    )
    from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
        StoredDeployManagerBackendInstallationContext,
        StoredDeployManagerBackendInstallationPlan,
    )
    from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
        StoredDeployPostManagerBackendLocalInstallReconciliation,
    )
    from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
        StoredDeployManagerBackendPreflightReconciliation,
    )
    from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
        StoredDeployManagerBackendStorageAllocationContext,
        StoredDeployManagerBackendStorageAllocationPlan,
    )
    from scylla_vms.ansible.deploy_manager_backend_storage_discovery_reconciliation import (
        StoredDeployManagerBackendStorageDiscoveryReconciliation,
    )
    from scylla_vms.ansible.deploy_manager_backend_storage_preflight_execution import (
        StoredDeployManagerBackendStoragePreflightEvidence,
        StoredDeployManagerBackendStoragePreflightExecution,
    )
    from scylla_vms.ansible.deploy_manager_backend_storage_preflight_plan import (
        StoredDeployManagerBackendStoragePreflightContext,
        StoredDeployManagerBackendStoragePreflightPlan,
    )
    from scylla_vms.ansible.deploy_manager_backend_storage_preflight_reconciliation import (
        StoredDeployManagerBackendStoragePreflightReconciliation,
    )
    from scylla_vms.ansible.deploy_reboot import DeployRebootResult
    from scylla_vms.ansible.evidence import CollectedEvidence
    from scylla_vms.ansible.jump_host_configure import (
        JumpHostConfigurationAuthorization,
        JumpHostConfigureEvidence,
    )
    from scylla_vms.ansible.manager_agent import ManagerAgentEvidence
    from scylla_vms.ansible.manager_backend_local_install import (
        ManagerBackendLocalInstallEvidence,
    )
    from scylla_vms.ansible.manager_backend_preflight import (
        ManagerBackendPreflightEvidence,
    )
    from scylla_vms.ansible.manager_backend_storage_discover import (
        ManagerBackendStorageDiscoveryEvidence,
    )
    from scylla_vms.ansible.manager_backend_storage_preflight import (
        ManagerBackendStoragePreflightEvidence,
    )
    from scylla_vms.ansible.manager_backend_storage_prepare import (
        ManagerBackendStoragePreparationAuthorization,
        ManagerBackendStoragePrepareEvidence,
    )
    from scylla_vms.ansible.manager_server import ManagerServerEvidence
    from scylla_vms.ansible.manager_tasks import ManagerTasksEvidence
    from scylla_vms.ansible.monitoring_agent import MonitoringAgentEvidence
    from scylla_vms.ansible.monitoring_stack import MonitoringStackEvidence
    from scylla_vms.ansible.monitoring_targets import MonitoringTargetsEvidence
    from scylla_vms.ansible.orchestration import (
        AnsibleOperationPlan,
        AnsibleStepIntent,
    )
    from scylla_vms.ansible.os_reprovision_prepare import (
        OsReprovisionCurrentProviderFacts,
        OsReprovisionPrepareAuthorization,
        OsReprovisionPrepareEvidence,
        OsReprovisionRoleSafetyEvidence,
    )
    from scylla_vms.ansible.os_upgrade_in_place import (
        OsUpgradeInPlaceAuthorization,
        OsUpgradeInPlaceEvidence,
    )
    from scylla_vms.ansible.os_upgrade_postcheck import OsUpgradePostcheckEvidence
    from scylla_vms.ansible.os_upgrade_preflight import (
        OsUpgradePreflightEvidence,
        OsUpgradePreflightIntent,
        OsUpgradePreflightPrerequisites,
    )
    from scylla_vms.ansible.routed_keyscan import RoutedKeyscanExecutionEvidence
    from scylla_vms.ansible.scylla_bootstrap import (
        ScyllaBootstrapAuthorization,
        ScyllaBootstrapEvidence,
    )
    from scylla_vms.ansible.scylla_cleanup import (
        CleanupTopologyChangeEvidence,
        ScyllaCleanupAuthorization,
        ScyllaCleanupEvidence,
    )
    from scylla_vms.ansible.scylla_cluster_shutdown import (
        ScyllaClusterShutdownAuthorization,
        ScyllaClusterShutdownEvidence,
    )
    from scylla_vms.ansible.scylla_configure import (
        ScyllaConfigureEvidence,
        ScyllaSeedPolicy,
    )
    from scylla_vms.ansible.scylla_health import ScyllaHealthEvidence
    from scylla_vms.ansible.scylla_install import ScyllaInstallEvidence
    from scylla_vms.ansible.scylla_remove_dead import (
        DeadTargetEvidence,
        ScyllaRemoveDeadAuthorization,
        ScyllaRemoveDeadEvidence,
    )
    from scylla_vms.ansible.scylla_remove_live import (
        ScyllaRemovalSafetyEvidence,
        ScyllaRemoveLiveAuthorization,
        ScyllaRemoveLiveEvidence,
    )
    from scylla_vms.ansible.scylla_repair import (
        ScyllaRepairAuthorization,
        ScyllaRepairEvidence,
    )
    from scylla_vms.ansible.scylla_replace_dead import (
        RepairBasedNodeOperationsEvidence,
        ReplacementTargetEvidence,
        ScyllaReplaceDeadAuthorization,
        ScyllaReplaceDeadEvidence,
    )
    from scylla_vms.ansible.service_converge import (
        ServiceConvergeEvidence,
        ServiceConvergePrerequisites,
    )
    from scylla_vms.ansible.storage import StorageDiscoveryEvidence
    from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
    from scylla_vms.ansible.storage_preflight import StoragePreflightResult
    from scylla_vms.ansible.storage_prepare import (
        StoragePreparationAuthorization,
        StoragePrepareEvidence,
    )
    from scylla_vms.ansible.storage_retire import (
        StorageRetireEvidence,
        StorageRetirementAuthorization,
    )
    from scylla_vms.desired import ImageFilter
    from scylla_vms.terraform.inputs import StoredTerraformInput


class ProcessRunnerProtocol(Protocol):
    def run(self, spec: ProcessSpec) -> ProcessResult:
        """Run one fully controlled process request."""


class HeldClusterLockProtocol(Protocol):
    def assert_held_for(self, paths: StatePaths) -> None:
        """Prove this lock protects the requested canonical state."""


class AnsibleResultError(AnsibleError):
    """Controlled execution completed without strict parseable result evidence."""


@dataclass(frozen=True, slots=True)
class AnsibleExecutionResult:
    playbook: str
    classification: OperationClassification
    check_mode: bool
    exit_code: int
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)
    inventory_preflight: "InventoryPreflightEvidence | None" = None
    connectivity: "ConnectivityEvidence | None" = None
    evidence: "CollectedEvidence | None" = None
    base_os: "BaseOsEvidence | None" = None
    storage_discovery: "StorageDiscoveryEvidence | None" = None
    storage_preflight: "StoragePreflightResult | None" = None
    storage_prepare: "StoragePrepareEvidence | None" = None
    storage_postcheck: "StoragePostcheckEvidence | None" = None
    storage_retire: "StorageRetireEvidence | None" = None
    scylla_install: "ScyllaInstallEvidence | None" = None
    scylla_configure: "ScyllaConfigureEvidence | None" = None
    scylla_bootstrap: "ScyllaBootstrapEvidence | None" = None
    scylla_health: "ScyllaHealthEvidence | None" = None
    scylla_remove_live: "ScyllaRemoveLiveEvidence | None" = None
    scylla_remove_dead: "ScyllaRemoveDeadEvidence | None" = None
    scylla_replace_dead: "ScyllaReplaceDeadEvidence | None" = None
    scylla_repair: "ScyllaRepairEvidence | None" = None
    scylla_cleanup: "ScyllaCleanupEvidence | None" = None
    scylla_cluster_shutdown: "ScyllaClusterShutdownEvidence | None" = None
    jump_host_configure: "JumpHostConfigureEvidence | None" = None
    manager_agent: "ManagerAgentEvidence | None" = None
    manager_server: "ManagerServerEvidence | None" = None
    manager_backend_preflight: "ManagerBackendPreflightEvidence | None" = None
    manager_backend_local_install: "ManagerBackendLocalInstallEvidence | None" = None
    manager_backend_storage_discovery: "ManagerBackendStorageDiscoveryEvidence | None" = None
    manager_backend_storage_preflight: "ManagerBackendStoragePreflightEvidence | None" = None
    manager_backend_storage_prepare: "ManagerBackendStoragePrepareEvidence | None" = (
        None
    )
    manager_tasks: "ManagerTasksEvidence | None" = None
    monitoring_agent: "MonitoringAgentEvidence | None" = None
    monitoring_stack: "MonitoringStackEvidence | None" = None
    monitoring_targets: "MonitoringTargetsEvidence | None" = None
    service_converge: "ServiceConvergeEvidence | None" = None
    os_upgrade_preflight: "OsUpgradePreflightEvidence | None" = None
    os_upgrade_in_place: "OsUpgradeInPlaceEvidence | None" = None
    os_reprovision_prepare: "OsReprovisionPrepareEvidence | None" = None
    os_upgrade_postcheck: "OsUpgradePostcheckEvidence | None" = None
    routed_keyscan: "RoutedKeyscanExecutionEvidence | None" = None
    deploy_reboot: "DeployRebootResult | None" = None


class ConnectivityStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL_FAILURE = "partial-failure"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class InventoryPreflightEvidence:
    status: str
    host_count: int
    target_count: int
    inventory_generation: int
    inventory_file_digest: str
    observation_generation: int
    observation_digest: str
    schema_version: str = "deploy-scylla-vms.ansible-inventory-preflight/v1"


class HostConnectivityStatus(StrEnum):
    REACHABLE = "reachable"
    FAILED = "failed"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class HostConnectivityEvidence:
    logical_id: str
    status: HostConnectivityStatus


@dataclass(frozen=True, slots=True)
class ConnectivityEvidence:
    status: ConnectivityStatus
    hosts: tuple[HostConnectivityEvidence, ...]
    destination_probes: tuple["DestinationProbeEvidence", ...] = ()


class DestinationProbeStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_PERFORMED = "not-performed"


@dataclass(frozen=True, slots=True)
class DestinationProbeEvidence:
    jump_host_id: str
    target_logical_id: str
    role: str
    port: int
    status: DestinationProbeStatus


_RECAP_LINE = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=(?P<ok>[0-9]+)\s+changed=(?P<changed>[0-9]+)\s+"
    r"unreachable=(?P<unreachable>[0-9]+)\s+failed=(?P<failed>[0-9]+)\s+"
    r"skipped=(?P<skipped>[0-9]+)\s+rescued=(?P<rescued>[0-9]+)\s+"
    r"ignored=(?P<ignored>[0-9]+)\s*$"
)
_DESTINATION_EVIDENCE = re.compile(
    r"DSV_TCP\s+"
    r"(?P<jump>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s+"
    r"(?P<target>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s+"
    r"(?P<role>scylla|manager|monitoring)\s+"
    r"(?P<port>[0-9]{1,5})\s+"
    r'(?P<status>passed|failed)"(?:\})?\s*$'
)
_INVENTORY_PREFLIGHT_MARKER = re.compile(
    r"DSV_INVENTORY_PREFLIGHT_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"
)


class AnsibleService:
    def __init__(
        self, builder: AnsibleCommandBuilder, runner: ProcessRunnerProtocol
    ) -> None:
        self._builder = builder
        self._runner = runner
        self._toolchain: AnsibleToolchain | None = None

    @property
    def command_builder(self) -> AnsibleCommandBuilder:
        """Return the exact anchored builder used by this service."""

        return self._builder

    def version(self, lock: HeldClusterLockProtocol) -> AnsibleToolchain:
        lock.assert_held_for(self._builder.paths)
        playbook = parse_ansible_core_version(
            self._run(self._builder.playbook_version(), prerequisite=True).stdout,
            expected_executable="ansible-playbook",
        )
        inventory = parse_ansible_core_version(
            self._run(self._builder.inventory_version(), prerequisite=True).stdout,
            expected_executable="ansible-inventory",
        )
        if playbook != inventory:
            raise AnsibleError("Ansible executable core versions conflict")
        self._toolchain = AnsibleToolchain(playbook)
        return self._toolchain

    def validate_inventory(
        self,
        lock: HeldClusterLockProtocol,
        observed: StoredObservedState,
        stored: StoredInventoryRecord,
        trust: StoredTrustRecord | None,
    ) -> ReadinessReport:
        lock.assert_held_for(self._builder.paths)
        self._require_toolchain()
        listed = self._run(self._protect_output(self._builder.inventory_list(), stored))
        graphed = self._run(
            self._protect_output(self._builder.inventory_graph(), stored)
        )
        try:
            evidence = validate_inventory_machine_output(
                listed.stdout,
                graphed.stdout,
                stored,
                protected_values=self._inventory_protected_values(stored),
            )
        except (AnsibleError, StateConflictError):
            return build_readiness_report(
                observed, stored, trust, machine_conflict=True
            )
        if trust is not None:
            try:
                TrustStore(self._builder.paths).validate_runtime(trust, stored)
            except (StateConflictError, StatePersistenceError):
                return build_readiness_report(
                    observed, stored, trust, trust_conflict=True
                )
        return build_readiness_report(
            observed, stored, trust, machine_evidence=evidence
        )

    def validate_inventory_list(
        self,
        lock: HeldClusterLockProtocol,
        observed: StoredObservedState,
        stored: StoredInventoryRecord,
        trust: StoredTrustRecord,
    ) -> tuple[ReadinessReport, InventoryListMachineEvidence]:
        """Strictly validate only local ``ansible-inventory --list`` evidence."""

        lock.assert_held_for(self._builder.paths)
        self._require_toolchain()
        listed = self._run(self._protect_output(self._builder.inventory_list(), stored))
        evidence = validate_inventory_list_output(
            listed.stdout,
            stored,
            protected_values=self._inventory_protected_values(stored),
        )
        TrustStore(self._builder.paths).validate_runtime(trust, stored)
        return (
            build_readiness_report(
                observed,
                stored,
                trust,
                machine_evidence=evidence,
            ),
            evidence,
        )

    def plan_operation(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        inventory: StoredInventoryRecord,
        operation_name: str,
        *,
        readiness: ReadinessReport,
        active_conditions: tuple[str, ...],
        intents: tuple["AnsibleStepIntent", ...],
    ) -> "AnsibleOperationPlan":
        """Resolve a lock-bound plan without runtime files or process execution."""

        from scylla_vms.ansible.orchestration import build_ansible_operation_plan

        return build_ansible_operation_plan(
            lock,
            self._builder,
            metadata,
            inventory,
            operation_name,
            readiness=readiness,
            active_conditions=active_conditions,
            intents=intents,
        )

    def syntax_check(self, lock: HeldClusterLockProtocol, name: str) -> ProcessResult:
        """Run syntax validation for one available registry source."""

        lock.assert_held_for(self._builder.paths)
        self._require_toolchain()
        return self._run(self._builder.syntax_check(name))

    def execute(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        inventory: StoredInventoryRecord,
        name: str,
        *,
        limit: tuple[str, ...],
        variables: dict[str, object],
        readiness: ReadinessReport,
        health_gate_passed: bool = False,
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        lock.assert_held_for(self._builder.paths)
        self._require_toolchain()
        definition = get_playbook(name)
        if not definition.source_available:
            raise AnsibleError(f"Ansible playbook source is unavailable: {name}")
        if (
            metadata.cluster_uuid != inventory.record.cluster_uuid
            or metadata.cluster_name != inventory.record.cluster_name
            or metadata.provider != inventory.record.provider
        ):
            raise StateConflictError("Ansible state identities conflict")
        if (
            readiness.inventory_generation != inventory.record.generation
            or readiness.inventory_digest != inventory.digest
        ):
            raise StateConflictError("Ansible readiness does not match inventory")
        if name == "inventory-preflight":
            self._require_inventory_preflight_ready(readiness)
        elif name == "routed-keyscan":
            self._require_routed_keyscan_ready(readiness)
        else:
            readiness.require_ready(definition.classification)
        if definition.pre_health_gate and not health_gate_passed:
            raise StateConflictError("Ansible pre-execution health gate is unsatisfied")
        self._validate_limit_membership(definition.hosts, limit, inventory)
        validated = definition.validate_variables(variables)
        if name == "connectivity-check":
            self._validate_destination_probes(validated, inventory, limit)
        elif name == "routed-keyscan":
            self._validate_routed_keyscan_request(
                metadata, inventory, readiness, validated, limit
            )
        runtime_values = self._runtime_variables(name, inventory, limit)
        for variable_name in set(validated) & set(runtime_values):
            if validated[variable_name] != runtime_values[variable_name]:
                raise StateConflictError(
                    "Ansible caller variables conflict with validated state"
                )
        validated.update(runtime_values)
        runtime_file = self._write_extra_vars(validated)
        try:
            command = self._builder.playbook(
                name,
                limit=limit,
                extra_vars_path=runtime_file,
                tags=tags,
                check=check,
                diff=diff,
                verbosity=verbosity,
            )
            command = self._protect_output(
                command,
                inventory,
                # Routed result bindings are public digests echoed by the strict
                # parser. Inventory protection still redacts every endpoint and
                # provider identity from process output and diagnostics.
                None if name == "routed-keyscan" else validated,
            )
            result = self._run(command)
        finally:
            self._remove_runtime_file(runtime_file)
        try:
            connectivity = (
                parse_connectivity_evidence(
                    result.stdout,
                    limit,
                    result.exit_code,
                    expected_probes=_probe_tuples(validated),
                )
                if name == "connectivity-check"
                else None
            )
            inventory_preflight = (
                parse_inventory_preflight_evidence(
                    result.stdout,
                    inventory,
                    limit,
                    result.exit_code,
                )
                if name == "inventory-preflight"
                else None
            )
            evidence = None
            if name == "evidence-collect":
                from scylla_vms.ansible.evidence import parse_collected_evidence

                evidence = parse_collected_evidence(
                    result.stdout, inventory, limit, result.exit_code
                )
            base_os = None
            if name == "base-os":
                from scylla_vms.ansible.base_os import parse_base_os_evidence

                base_os = parse_base_os_evidence(result.stdout, limit, result.exit_code)
            storage_discovery = None
            if name == "storage-discover":
                from scylla_vms.ansible.storage import (
                    parse_storage_discovery_evidence,
                )

                storage_discovery = parse_storage_discovery_evidence(
                    result.stdout, inventory, limit, result.exit_code
                )
            routed_keyscan = None
            if name == "routed-keyscan":
                from scylla_vms.ansible.routed_keyscan import (
                    parse_routed_keyscan_execution,
                )

                payload = validated.get("deploy_scylla_vms_routed_keyscan")
                if not isinstance(payload, dict):
                    raise AnsibleError("routed SSH keyscan request is unavailable")
                routed_keyscan = parse_routed_keyscan_execution(
                    result.stdout,
                    payload,
                    limit[0],
                    result.exit_code,
                )
            deploy_reboot = None
            if name == "deploy-reboot":
                from scylla_vms.ansible.deploy_reboot import (
                    parse_deploy_reboot_result,
                )

                payload = validated.get("deploy_scylla_vms_deploy_reboot")
                if not isinstance(payload, dict):
                    raise AnsibleError("deploy reboot request is unavailable")
                deploy_reboot = parse_deploy_reboot_result(
                    result.stdout,
                    payload,
                    result.exit_code,
                )
        except AnsibleError as error:
            raise AnsibleResultError(
                "Ansible command returned malformed strict result evidence"
            ) from error
        projected = (
            inventory_preflight is not None
            or connectivity is not None
            or evidence is not None
            or base_os is not None
            or storage_discovery is not None
            or routed_keyscan is not None
            or deploy_reboot is not None
        )
        return AnsibleExecutionResult(
            playbook=name,
            classification=definition.classification,
            check_mode=check,
            exit_code=result.exit_code,
            stdout="" if projected else result.stdout,
            stderr="" if projected else result.stderr,
            inventory_preflight=inventory_preflight,
            connectivity=connectivity,
            evidence=evidence,
            base_os=base_os,
            storage_discovery=storage_discovery,
            routed_keyscan=routed_keyscan,
            deploy_reboot=deploy_reboot,
        )

    def execute_operation_step(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        inventory: StoredInventoryRecord,
        name: str,
        *,
        step_sequence: int,
        limit: tuple[str, ...],
        variables: dict[str, object],
        readiness: ReadinessReport,
        health_gate_passed: bool = False,
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> tuple[AnsibleExecutionResult, str]:
        """Execute one immutable operation command through this service boundary."""

        _, validated, _, command_digest = self._builder.validate_operation_step(
            name,
            step_sequence=step_sequence,
            limit=limit,
            variables=variables,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )
        result = self.execute(
            lock,
            metadata,
            inventory,
            name,
            limit=limit,
            variables=validated,
            readiness=readiness,
            health_gate_passed=health_gate_passed,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )
        return result, command_digest

    def execute_storage_preflight(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        discovery: "StorageDiscoveryEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Run the read-only projection after exact local reconciliation."""

        from scylla_vms.ansible.storage_preflight import (
            parse_storage_preflight_execution,
            reconcile_storage_preflight,
        )

        lock.assert_held_for(self._builder.paths)
        expected = reconcile_storage_preflight(
            metadata, observed, inventory, discovery, limit
        )
        variable = {host.logical_id: host.to_object() for host in expected.hosts}
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "storage-preflight",
            limit=limit,
            variables={"deploy_scylla_vms_storage_preflight": variable},
            readiness=readiness,
            check=True,
            verbosity=verbosity,
        )
        parsed = parse_storage_preflight_execution(
            executed.stdout, expected, executed.exit_code
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            storage_preflight=parsed,
        )

    def execute_storage_prepare(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        discovery: "StorageDiscoveryEvidence",
        preflight: "StoragePreflightResult",
        authorization: "StoragePreparationAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Run one destructive preparation only after exact local authorization."""

        from scylla_vms.ansible.storage_prepare import (
            build_storage_prepare_payload,
            parse_storage_prepare_execution,
        )

        lock.assert_held_for(self._builder.paths)
        payload = build_storage_prepare_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            authorization,
            limit=limit,
            check=False,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "storage-prepare",
            limit=limit,
            variables={"deploy_scylla_vms_storage_prepare": payload},
            readiness=readiness,
            check=False,
            verbosity=verbosity,
        )
        host = preflight.hosts[0]
        parsed = parse_storage_prepare_execution(
            executed.stdout,
            expected_logical_id=host.logical_id,
            expected_backend=host.backend,
            expected_layout=host.layout,
            expected_device_set_digest=authorization.device_set_digest,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            storage_prepare=parsed,
        )

    def execute_storage_postcheck(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        discovery: "StorageDiscoveryEvidence",
        preflight: "StoragePreflightResult",
        preparation: "StoragePrepareEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Run one read-only exact verification after storage preparation."""

        from scylla_vms.ansible.storage_postcheck import (
            build_storage_postcheck_payload,
            parse_storage_postcheck_execution,
        )

        lock.assert_held_for(self._builder.paths)
        payload = build_storage_postcheck_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            limit=limit,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "storage-postcheck",
            limit=limit,
            variables={"deploy_scylla_vms_storage_postcheck": payload},
            readiness=readiness,
            check=True,
            verbosity=verbosity,
        )
        parsed = parse_storage_postcheck_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            storage_postcheck=parsed,
        )

    def execute_storage_retire(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        discovery: "StorageDiscoveryEvidence",
        preflight: "StoragePreflightResult",
        preparation: "StoragePrepareEvidence",
        postcheck: "StoragePostcheckEvidence",
        authorization: "StorageRetirementAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Run one destructive retirement only after exact local authorization."""

        from scylla_vms.ansible.storage_retire import (
            build_storage_retire_payload,
            parse_storage_retire_execution,
        )

        lock.assert_held_for(self._builder.paths)
        payload = build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            authorization,
            readiness,
            limit=limit,
            check=False,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "storage-retire",
            limit=limit,
            variables={"deploy_scylla_vms_storage_retire": payload},
            readiness=readiness,
            check=False,
            verbosity=verbosity,
        )
        parsed = parse_storage_retire_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            storage_retire=parsed,
        )

    def execute_jump_host_configure(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        trust: StoredTrustRecord,
        base_os: "BaseOsEvidence",
        authorization: "JumpHostConfigurationAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Harden exactly one authorized jump host for inventory-derived ProxyJump."""

        from scylla_vms.ansible.jump_host_configure import (
            build_jump_host_configure_payload,
            parse_jump_host_configure_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1 or limit[0] != authorization.target_logical_id:
            raise StateConflictError(
                "jump-host configuration requires one exact jump ID"
            )
        payload = build_jump_host_configure_payload(
            metadata,
            observed,
            inventory,
            trust,
            readiness,
            base_os,
            authorization,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "jump-host-configure",
            limit=limit,
            variables={"deploy_scylla_vms_jump_host_configure": payload},
            readiness=readiness,
            tags=("jump-host-configure",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_jump_host_configure_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            jump_host_configure=parsed,
        )

    def execute_manager_agent(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        scylla_install: "ScyllaInstallEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        package_version: str,
        cluster_spec_digest: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Install one exact Manager agent package after prerequisite evidence matches."""

        from scylla_vms.ansible.manager_agent import (
            build_manager_agent_payload,
            parse_manager_agent_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("Manager agent install requires one exact target")
        payload = build_manager_agent_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            scylla_install,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            package_version=package_version,
            cluster_spec_digest=cluster_spec_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-agent",
            limit=limit,
            variables={"deploy_scylla_vms_manager_agent": payload},
            readiness=readiness,
            tags=("manager-agent",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_agent_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_agent=parsed,
        )

    def execute_manager_server(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        package_version: str,
        cluster_spec_digest: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Install exact Manager server packages after prerequisite evidence matches."""

        from scylla_vms.ansible.manager_server import (
            build_manager_server_payload,
            parse_manager_server_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("Manager server install requires one exact target")
        payload = build_manager_server_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            package_version=package_version,
            cluster_spec_digest=cluster_spec_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-server",
            limit=limit,
            variables={"deploy_scylla_vms_manager_server": payload},
            readiness=readiness,
            tags=("manager-server",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_server_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_server=parsed,
        )

    def execute_manager_backend_preflight(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        manager_server: "ManagerServerEvidence",
        backend_context: "StoredDeployManagerBackendConfigurationContext",
        backend_plan: "StoredDeployManagerBackendConfigurationPlan",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Inspect one Manager host for later local-backend installation planning."""

        from scylla_vms.ansible.manager_backend_preflight import (
            build_manager_backend_preflight_payload,
            parse_manager_backend_preflight_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "Manager backend preflight requires one exact target"
            )
        payload = build_manager_backend_preflight_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            manager_server,
            backend_context,
            backend_plan,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-backend-preflight",
            limit=limit,
            variables={"deploy_scylla_vms_manager_backend_preflight": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("manager-backend-preflight",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_backend_preflight_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_backend_preflight=parsed,
        )

    def execute_manager_backend_local_install(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        manager_server: "ManagerServerEvidence",
        preflight_reconciliation: ("StoredDeployManagerBackendPreflightReconciliation"),
        installation_context: "StoredDeployManagerBackendInstallationContext",
        installation_plan: "StoredDeployManagerBackendInstallationPlan",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Install only the exact Manager-local Scylla backend packages."""

        from scylla_vms.ansible.manager_backend_local_install import (
            build_manager_backend_local_install_payload,
            parse_manager_backend_local_install_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "Manager backend local install requires one exact target"
            )
        payload = build_manager_backend_local_install_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            manager_server,
            preflight_reconciliation,
            installation_context,
            installation_plan,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-backend-local-install",
            limit=limit,
            variables={"deploy_scylla_vms_manager_backend_local_install": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("manager-backend-local-install",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_backend_local_install_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_backend_local_install=parsed,
        )

    def execute_manager_backend_storage_discovery(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        terraform_input: "StoredTerraformInput",
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        allocation_context: "StoredDeployManagerBackendStorageAllocationContext",
        allocation_plan: "StoredDeployManagerBackendStorageAllocationPlan",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Inspect one exact Manager backend volume without mutation."""

        from scylla_vms.ansible.manager_backend_storage_discover import (
            build_manager_backend_storage_discovery_payload,
            parse_manager_backend_storage_discovery_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "Manager backend storage discovery requires one exact target"
            )
        payload = build_manager_backend_storage_discovery_payload(
            metadata,
            terraform_input,
            observed,
            inventory,
            readiness,
            allocation_context,
            allocation_plan,
            logical_id=limit[0],
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-backend-storage-discover",
            limit=limit,
            variables={"deploy_scylla_vms_manager_backend_storage_discover": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("manager-backend-storage-discover",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_backend_storage_discovery_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_backend_storage_discovery=parsed,
        )

    def execute_manager_backend_storage_preflight(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        terraform_input: "StoredTerraformInput",
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        discovery: "StoredDeployManagerBackendStorageDiscoveryReconciliation",
        preflight_context: "StoredDeployManagerBackendStoragePreflightContext",
        preflight_plan: "StoredDeployManagerBackendStoragePreflightPlan",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Inspect one planned Manager backend layout without mutation."""

        from scylla_vms.ansible.manager_backend_storage_preflight import (
            build_manager_backend_storage_preflight_payload,
            parse_manager_backend_storage_preflight_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if limit != (preflight_plan.record.manager_target_id,):
            raise StateConflictError(
                "Manager backend storage preflight requires its exact planned target"
            )
        payload = build_manager_backend_storage_preflight_payload(
            metadata,
            terraform_input,
            observed,
            inventory,
            readiness,
            discovery,
            preflight_context,
            preflight_plan,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-backend-storage-preflight",
            limit=limit,
            variables={"deploy_scylla_vms_manager_backend_storage_preflight": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("manager-backend-storage-preflight",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_backend_storage_preflight_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_backend_storage_preflight=parsed,
        )

    def execute_manager_backend_storage_prepare(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        terraform_input: "StoredTerraformInput",
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        package_reconciliation: "StoredDeployPostManagerBackendLocalInstallReconciliation",
        preflight_execution: "StoredDeployManagerBackendStoragePreflightExecution",
        preflight_evidence: "StoredDeployManagerBackendStoragePreflightEvidence",
        preflight_reconciliation: "StoredDeployManagerBackendStoragePreflightReconciliation",
        authorization: "ManagerBackendStoragePreparationAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Apply one exact typed Manager-local storage preparation request."""

        from scylla_vms.ansible.manager_backend_storage_prepare import (
            build_manager_backend_storage_prepare_payload,
            parse_manager_backend_storage_prepare_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if limit != (authorization.stable_id,):
            raise StateConflictError(
                "Manager backend storage preparation requires its exact target"
            )
        payload = build_manager_backend_storage_prepare_payload(
            metadata,
            terraform_input,
            observed,
            inventory,
            readiness,
            package_reconciliation,
            preflight_execution,
            preflight_evidence,
            preflight_reconciliation,
            authorization,
            limit=limit,
            check=check,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-backend-storage-prepare",
            limit=limit,
            variables={"deploy_scylla_vms_manager_backend_storage_prepare": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("manager-backend-storage-prepare",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_backend_storage_prepare_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_backend_storage_prepare=parsed,
        )

    def execute_manager_tasks(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        manager_server: "ManagerServerEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        cluster_spec_digest: str,
        action: str = "inspect",
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Validate Manager task intent and refuse live API use when inactive."""

        from scylla_vms.ansible.manager_tasks import (
            build_manager_tasks_payload,
            parse_manager_tasks_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "Manager task validation requires one exact target"
            )
        payload = build_manager_tasks_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            manager_server,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            cluster_spec_digest=cluster_spec_digest,
            action=action,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "manager-tasks",
            limit=limit,
            variables={"deploy_scylla_vms_manager_tasks": payload},
            readiness=readiness,
            tags=("manager-tasks",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_manager_tasks_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            manager_tasks=parsed,
        )

    def execute_monitoring_agent(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        scylla_install: "ScyllaInstallEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        package_version: str,
        cluster_spec_digest: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Install one exact node-exporter package after prerequisite evidence matches."""

        from scylla_vms.ansible.monitoring_agent import (
            build_monitoring_agent_payload,
            parse_monitoring_agent_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "Monitoring agent install requires one exact target"
            )
        payload = build_monitoring_agent_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            scylla_install,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            package_version=package_version,
            cluster_spec_digest=cluster_spec_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "monitoring-agent",
            limit=limit,
            variables={"deploy_scylla_vms_monitoring_agent": payload},
            readiness=readiness,
            tags=("monitoring-agent",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_monitoring_agent_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            monitoring_agent=parsed,
        )

    def execute_monitoring_stack(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        stack_version: str,
        cluster_spec_digest: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Install one exact Monitoring stack archive after prerequisites match."""

        from scylla_vms.ansible.monitoring_stack import (
            build_monitoring_stack_payload,
            parse_monitoring_stack_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "Monitoring stack install requires one exact target"
            )
        payload = build_monitoring_stack_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            stack_version=stack_version,
            cluster_spec_digest=cluster_spec_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "monitoring-stack",
            limit=limit,
            variables={"deploy_scylla_vms_monitoring_stack": payload},
            readiness=readiness,
            tags=("monitoring-stack",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_monitoring_stack_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            monitoring_stack=parsed,
        )

    def execute_monitoring_targets(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        monitoring_stack: "MonitoringStackEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        cluster_spec_digest: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Generate official Monitoring 4.16.0 target files after prerequisites match."""

        from scylla_vms.ansible.monitoring_targets import (
            build_monitoring_targets_payload,
            parse_monitoring_targets_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "Monitoring target generation requires one exact target"
            )
        payload = build_monitoring_targets_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            monitoring_stack,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            cluster_spec_digest=cluster_spec_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "monitoring-targets",
            limit=limit,
            variables={"deploy_scylla_vms_monitoring_targets": payload},
            readiness=readiness,
            tags=("monitoring-targets",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_monitoring_targets_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            monitoring_targets=parsed,
        )

    def execute_service_converge(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        prerequisites: "ServiceConvergePrerequisites",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        cluster_spec_digest: str,
        service_scope: str,
        restart_policy: str = "if-required",
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Reconcile allowlisted unit state without unreviewed starts."""

        from scylla_vms.ansible.service_converge import (
            build_service_converge_payload,
            parse_service_converge_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("service-converge requires one exact target")
        payload = build_service_converge_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            cluster_spec_digest=cluster_spec_digest,
            service_scope=service_scope,
            restart_policy=restart_policy,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "service-converge",
            limit=limit,
            variables={
                "deploy_scylla_vms_restart_policy": restart_policy,
                "deploy_scylla_vms_service_converge": payload,
                "deploy_scylla_vms_service_scope": service_scope,
            },
            readiness=readiness,
            health_gate_passed=True,
            tags=("service-converge",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_service_converge_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            service_converge=parsed,
        )

    def execute_scylla_install(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        storage_postcheck: "StoragePostcheckEvidence",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        package_version: str,
        cluster_spec_digest: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Install one exact package set after all prerequisite evidence matches."""

        from scylla_vms.ansible.scylla_install import (
            build_scylla_install_payload,
            parse_scylla_install_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("Scylla install requires one exact target")
        payload = build_scylla_install_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            storage_postcheck,
            logical_id=limit[0],
            image_filter=image_filter,
            architecture=architecture,
            package_version=package_version,
            cluster_spec_digest=cluster_spec_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-install",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_install": payload},
            readiness=readiness,
            tags=("scylla-install",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_scylla_install_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_install=parsed,
        )

    def execute_scylla_configure(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        storage_postcheck: "StoragePostcheckEvidence",
        scylla_install: "ScyllaInstallEvidence",
        seed_policy: "ScyllaSeedPolicy",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        package_version: str,
        architecture: str,
        cluster_spec_digest: str,
        prior_configuration: "ScyllaConfigureEvidence | None" = None,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Configure one exact stable ID without startup or bootstrap."""

        from scylla_vms.ansible.scylla_configure import (
            build_scylla_configure_payload,
            parse_scylla_configure_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("Scylla configure requires one exact target")
        payload = build_scylla_configure_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            storage_postcheck,
            scylla_install,
            seed_policy,
            logical_id=limit[0],
            package_version=package_version,
            architecture=architecture,
            cluster_spec_digest=cluster_spec_digest,
            prior_configuration=prior_configuration,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-configure",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_configure": payload},
            readiness=readiness,
            tags=("scylla-configure",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_scylla_configure_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_configure=parsed,
        )

    def execute_scylla_bootstrap(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        storage_postcheck: "StoragePostcheckEvidence",
        scylla_install: "ScyllaInstallEvidence",
        scylla_configure: "ScyllaConfigureEvidence",
        seed_policy: "ScyllaSeedPolicy",
        authorization: "ScyllaBootstrapAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        package_version: str,
        bootstrap_timeout_seconds: int,
        cluster_spec_digest: str,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Start and verify one explicitly authorized Scylla target."""

        from scylla_vms.ansible.scylla_bootstrap import (
            build_scylla_bootstrap_payload,
            parse_scylla_bootstrap_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1 or limit[0] != authorization.target_logical_id:
            raise StateConflictError("Scylla bootstrap requires one exact target")
        payload = build_scylla_bootstrap_payload(
            metadata,
            observed,
            inventory,
            readiness,
            storage_postcheck,
            scylla_install,
            scylla_configure,
            seed_policy,
            authorization,
            package_version=package_version,
            bootstrap_timeout_seconds=bootstrap_timeout_seconds,
            cluster_spec_digest=cluster_spec_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-bootstrap",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_bootstrap": payload},
            readiness=readiness,
            tags=("scylla-bootstrap",),
            check=False,
            verbosity=verbosity,
        )
        parsed = parse_scylla_bootstrap_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_bootstrap=parsed,
        )

    def execute_scylla_health(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        storage_postchecks: tuple["StoragePostcheckEvidence", ...],
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        timeout_seconds: int,
        known_host_ids: dict[str, str] | None = None,
        active_stable_ids: tuple[str, ...] | None = None,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Collect and reconcile bounded read-only cluster health views."""

        from scylla_vms.ansible.scylla_health import (
            build_scylla_health_payload,
            parse_scylla_health_execution,
        )

        lock.assert_held_for(self._builder.paths)
        payload = build_scylla_health_payload(
            metadata,
            observed,
            inventory,
            readiness,
            storage_postchecks,
            limit=limit,
            timeout_seconds=timeout_seconds,
            known_host_ids=known_host_ids,
            active_stable_ids=active_stable_ids,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-health",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_health": payload},
            readiness=readiness,
            tags=("scylla-health",),
            check=True,
            verbosity=verbosity,
        )
        parsed = parse_scylla_health_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_health=parsed,
        )

    def execute_scylla_remove_live(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        health: "ScyllaHealthEvidence",
        safety: "ScyllaRemovalSafetyEvidence",
        authorization: "ScyllaRemoveLiveAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        config_digest: str,
        storage_digest: str,
        decommission_timeout_seconds: int,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Decommission one live node after exact destructive authorization."""

        from scylla_vms.ansible.scylla_remove_live import (
            build_scylla_remove_live_payload,
            parse_scylla_remove_live_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1 or limit[0] != authorization.target_logical_id:
            raise StateConflictError("Scylla live removal requires one exact target")
        payload = build_scylla_remove_live_payload(
            metadata,
            observed,
            inventory,
            readiness,
            health,
            safety,
            authorization,
            config_digest=config_digest,
            storage_digest=storage_digest,
            decommission_timeout_seconds=decommission_timeout_seconds,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-remove-live",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_remove_live": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("scylla-remove-live",),
            check=False,
            verbosity=verbosity,
        )
        parsed = parse_scylla_remove_live_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_remove_live=parsed,
        )

    def execute_scylla_remove_dead(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        survivor_health: "ScyllaHealthEvidence",
        dead_target: "DeadTargetEvidence",
        safety: "ScyllaRemovalSafetyEvidence",
        authorization: "ScyllaRemoveDeadAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        timeout_seconds: int,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Remove one dead Host ID from one exact healthy coordinator."""

        from scylla_vms.ansible.scylla_remove_dead import (
            build_scylla_remove_dead_payload,
            parse_scylla_remove_dead_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if (
            len(limit) != 1
            or limit[0] != authorization.coordinator_stable_id
            or limit[0] == authorization.target_stable_id
        ):
            raise StateConflictError(
                "Scylla dead removal must limit only the selected survivor coordinator"
            )
        payload = build_scylla_remove_dead_payload(
            metadata,
            observed,
            inventory,
            readiness,
            survivor_health,
            dead_target,
            safety,
            authorization,
            timeout_seconds=timeout_seconds,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-remove-dead",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_remove_dead": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("scylla-remove-dead",),
            check=False,
            verbosity=verbosity,
        )
        parsed = parse_scylla_remove_dead_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_remove_dead=parsed,
        )

    def execute_scylla_replace_dead(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        survivor_health: "ScyllaHealthEvidence",
        target: "ReplacementTargetEvidence",
        safety: "ScyllaRemovalSafetyEvidence",
        storage: "StoragePostcheckEvidence",
        install: "ScyllaInstallEvidence",
        configure: "ScyllaConfigureEvidence",
        rbno: "RepairBasedNodeOperationsEvidence",
        authorization: "ScyllaReplaceDeadAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        package_version: str,
        timeout_seconds: int,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Start one exact newly provisioned replacement target."""

        from scylla_vms.ansible.scylla_replace_dead import (
            build_scylla_replace_dead_payload,
            parse_scylla_replace_dead_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1 or limit[0] != authorization.stable_id:
            raise StateConflictError(
                "Scylla replacement must limit only the new stable logical target"
            )
        payload = build_scylla_replace_dead_payload(
            metadata,
            observed,
            inventory,
            readiness,
            survivor_health,
            target,
            safety,
            storage,
            install,
            configure,
            rbno,
            authorization,
            package_version=package_version,
            timeout_seconds=timeout_seconds,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-replace-dead",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_replace_dead": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("scylla-replace-dead",),
            check=False,
            verbosity=verbosity,
        )
        parsed = parse_scylla_replace_dead_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_replace_dead=parsed,
        )

    def execute_scylla_repair(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        health: "ScyllaHealthEvidence",
        source_result: "ScyllaReplaceDeadEvidence | ScyllaBootstrapEvidence",
        rbno: "RepairBasedNodeOperationsEvidence",
        authorization: "ScyllaRepairAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        package_version: str,
        timeout_seconds: int,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Run one fixed foreground full repair on one exact stable ID."""

        from scylla_vms.ansible.scylla_repair import (
            build_scylla_repair_payload,
            parse_scylla_repair_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1 or limit[0] != authorization.stable_id:
            raise StateConflictError(
                "Scylla repair must limit only the exact authorized stable ID"
            )
        payload = build_scylla_repair_payload(
            metadata,
            observed,
            inventory,
            readiness,
            health,
            source_result,
            rbno,
            authorization,
            package_version=package_version,
            timeout_seconds=timeout_seconds,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-repair",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_repair": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("scylla-repair",),
            check=False,
            verbosity=verbosity,
        )
        parsed = parse_scylla_repair_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_repair=parsed,
        )

    def execute_scylla_cleanup(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        health: "ScyllaHealthEvidence",
        topology_change: "CleanupTopologyChangeEvidence",
        authorization: "ScyllaCleanupAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        package_version: str,
        timeout_seconds: int,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Run one fixed foreground cleanup on one exact eligible stable ID."""

        from scylla_vms.ansible.scylla_cleanup import (
            build_scylla_cleanup_payload,
            parse_scylla_cleanup_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1 or limit[0] != authorization.stable_id:
            raise StateConflictError(
                "Scylla cleanup must limit only the exact authorized stable ID"
            )
        payload = build_scylla_cleanup_payload(
            metadata,
            observed,
            inventory,
            readiness,
            health,
            topology_change,
            authorization,
            package_version=package_version,
            timeout_seconds=timeout_seconds,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-cleanup",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_cleanup": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("scylla-cleanup",),
            check=False,
            verbosity=verbosity,
        )
        parsed = parse_scylla_cleanup_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_cleanup=parsed,
        )

    def execute_scylla_cluster_shutdown(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        health: "ScyllaHealthEvidence",
        manager_tasks: "ManagerTasksEvidence",
        authorization: "ScyllaClusterShutdownAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Validate full-cluster shutdown gates and refuse unreviewed mutation."""

        from scylla_vms.ansible.scylla_cluster_shutdown import (
            build_scylla_cluster_shutdown_payload,
            parse_scylla_cluster_shutdown_execution,
        )

        lock.assert_held_for(self._builder.paths)
        payload = build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            readiness,
            health,
            manager_tasks,
            authorization,
            limit=limit,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "scylla-cluster-shutdown",
            limit=limit,
            variables={"deploy_scylla_vms_scylla_cluster_shutdown": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("scylla-cluster-shutdown",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_scylla_cluster_shutdown_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            scylla_cluster_shutdown=parsed,
        )

    def execute_os_upgrade_preflight(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        prerequisites: "OsUpgradePreflightPrerequisites",
        intent: "OsUpgradePreflightIntent",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Inspect one exact OS-upgrade target without authorizing mutation."""

        from scylla_vms.ansible.os_upgrade_preflight import (
            build_os_upgrade_preflight_payload,
            parse_os_upgrade_preflight_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("OS-upgrade preflight requires one exact target")
        payload = build_os_upgrade_preflight_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            intent,
            limit=limit,
            image_filter=image_filter,
            architecture=architecture,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "os-upgrade-preflight",
            limit=limit,
            variables={"deploy_scylla_vms_os_upgrade_preflight": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("os-upgrade-preflight",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_os_upgrade_preflight_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            os_upgrade_preflight=parsed,
        )

    def execute_os_upgrade_in_place(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        prerequisites: "OsUpgradePreflightPrerequisites",
        intent: "OsUpgradePreflightIntent",
        preflight: "OsUpgradePreflightEvidence",
        authorization: "OsUpgradeInPlaceAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Validate and return a blocked in-place OS-upgrade result."""

        from scylla_vms.ansible.os_upgrade_in_place import (
            build_os_upgrade_in_place_payload,
            parse_os_upgrade_in_place_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("OS-upgrade in-place requires one exact target")
        payload = build_os_upgrade_in_place_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            intent,
            preflight,
            authorization,
            limit=limit,
            image_filter=image_filter,
            architecture=architecture,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "os-upgrade-in-place",
            limit=limit,
            variables={"deploy_scylla_vms_os_upgrade_in_place": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("os-upgrade-in-place",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_os_upgrade_in_place_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            os_upgrade_in_place=parsed,
        )

    def execute_os_reprovision_prepare(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        prerequisites: "OsUpgradePreflightPrerequisites",
        intent: "OsUpgradePreflightIntent",
        preflight: "OsUpgradePreflightEvidence",
        current_provider: "OsReprovisionCurrentProviderFacts",
        role_safety: "OsReprovisionRoleSafetyEvidence",
        authorization: "OsReprovisionPrepareAuthorization",
        *,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Validate immutable reprovision intent and return blocked evidence."""

        from scylla_vms.ansible.os_reprovision_prepare import (
            build_os_reprovision_prepare_payload,
            parse_os_reprovision_prepare_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError(
                "OS-reprovision preparation requires one exact target"
            )
        payload = build_os_reprovision_prepare_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            intent,
            preflight,
            current_provider,
            role_safety,
            authorization,
            limit=limit,
            image_filter=image_filter,
            architecture=architecture,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "os-reprovision-prepare",
            limit=limit,
            variables={"deploy_scylla_vms_os_reprovision_prepare": payload},
            readiness=readiness,
            health_gate_passed=True,
            tags=("os-reprovision-prepare",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_os_reprovision_prepare_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            os_reprovision_prepare=parsed,
        )

    def execute_os_upgrade_postcheck(
        self,
        lock: HeldClusterLockProtocol,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        base_os: "BaseOsEvidence",
        prerequisites: "OsUpgradePreflightPrerequisites",
        source_result: "OsUpgradeInPlaceEvidence | OsReprovisionPrepareEvidence",
        source_authorization: (
            "OsUpgradeInPlaceAuthorization | OsReprovisionPrepareAuthorization"
        ),
        *,
        operation_id: str,
        limit: tuple[str, ...],
        readiness: ReadinessReport,
        image_filter: "ImageFilter",
        architecture: str,
        expected_kernel_release_digest: str | None = None,
        check: bool = False,
        verbosity: int = 0,
    ) -> AnsibleExecutionResult:
        """Verify one exact source result without host or provider remediation."""

        from scylla_vms.ansible.os_upgrade_postcheck import (
            build_os_upgrade_postcheck_payload,
            parse_os_upgrade_postcheck_execution,
        )

        lock.assert_held_for(self._builder.paths)
        if len(limit) != 1:
            raise StateConflictError("OS-upgrade postcheck requires one exact target")
        payload = build_os_upgrade_postcheck_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            source_result,
            source_authorization,
            operation_id=operation_id,
            limit=limit,
            image_filter=image_filter,
            architecture=architecture,
            expected_kernel_release_digest=expected_kernel_release_digest,
        )
        executed = self.execute(
            lock,
            metadata,
            inventory,
            "os-upgrade-postcheck",
            limit=limit,
            variables={"deploy_scylla_vms_os_upgrade_postcheck": payload},
            readiness=readiness,
            tags=("os-upgrade-postcheck",),
            check=check,
            verbosity=verbosity,
        )
        parsed = parse_os_upgrade_postcheck_execution(
            executed.stdout,
            expected_payload=payload,
            exit_code=executed.exit_code,
        )
        return replace(
            executed,
            stdout="",
            stderr="",
            os_upgrade_postcheck=parsed,
        )

    @staticmethod
    def _require_inventory_preflight_ready(readiness: ReadinessReport) -> None:
        if (
            readiness.source_status is not EvidenceStatus.FRESH
            or readiness.machine_status is not EvidenceStatus.FRESH
        ):
            raise StateConflictError(
                "Ansible inventory preflight requires fresh source and machine evidence"
            )

    @staticmethod
    def _require_routed_keyscan_ready(readiness: ReadinessReport) -> None:
        from scylla_vms.ansible.readiness import RouteReadiness, TrustReadiness

        if (
            readiness.source_status is not EvidenceStatus.FRESH
            or readiness.machine_status is not EvidenceStatus.FRESH
            or readiness.route_status is not RouteReadiness.VALID
            or readiness.trust_status
            not in {TrustReadiness.INCOMPLETE, TrustReadiness.COMPLETE}
        ):
            raise StateConflictError(
                "routed SSH keyscan requires fresh inventory, valid routes, "
                "and current jump trust"
            )

    def _validate_routed_keyscan_request(
        self,
        metadata: ClusterMetadata,
        inventory: StoredInventoryRecord,
        readiness: ReadinessReport,
        values: dict[str, object],
        limit: tuple[str, ...],
    ) -> None:
        from scylla_vms.ansible.routed_keyscan import (
            _readiness_digest,
            routed_keyscan_route_digest,
        )
        from scylla_vms.desired import HostRole

        payload = values.get("deploy_scylla_vms_routed_keyscan")
        if not isinstance(payload, dict) or len(limit) != 1:
            raise StateConflictError("routed SSH keyscan request is invalid")
        hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
        jump = hosts.get(limit[0])
        if (
            jump is None
            or jump.role is not HostRole.JUMP_HOST
            or jump.jump_host_id is not None
            or payload.get("jump_host_id") != jump.logical_id
        ):
            raise StateConflictError(
                "routed SSH keyscan requires one exact jump stable ID"
            )
        trust_store = TrustStore(self._builder.paths)
        trust = trust_store.read(
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
            expected_provider=metadata.provider,
        )
        if (
            trust.record.observation_generation
            != inventory.record.source_manifest_generation
            or trust.record.observation_digest
            != inventory.record.source_manifest_digest
            or trust.record.inventory_generation != inventory.record.generation
            or trust.record.inventory_digest != inventory.record.inventory_digest
            or readiness.trust_generation != trust.record.generation
            or readiness.trust_digest != trust.digest
        ):
            raise StateConflictError("routed SSH keyscan trust or readiness drifted")
        trust_store.validate_runtime(trust, inventory)
        trusted = {entry.logical_id: entry for entry in trust.record.entries}
        jump_trust = trusted.get(jump.logical_id)
        if jump_trust is None or (
            jump_trust.provider_id != jump.provider_id
            or jump_trust.endpoint.address != jump.ansible_host
            or jump_trust.endpoint.port != 22
            or jump_trust.jump_host_id is not None
        ):
            raise StateConflictError("routed SSH keyscan jump trust conflicts")
        provenance = payload.get("provenance")
        if not isinstance(provenance, dict) or provenance != {
            "inventory_digest": inventory.digest,
            "inventory_generation": inventory.record.generation,
            "observation_digest": inventory.record.source_manifest_digest,
            "observation_generation": inventory.record.source_manifest_generation,
            "readiness_digest": _readiness_digest(readiness),
            "readiness_schema_version": readiness.schema_version,
            "trust_digest": trust.digest,
            "trust_generation": trust.record.generation,
        }:
            raise StateConflictError("routed SSH keyscan provenance conflicts")
        target_values = payload.get("targets")
        if not isinstance(target_values, list):
            raise StateConflictError("routed SSH keyscan targets are invalid")
        expected: list[dict[str, object]] = []
        for value in target_values:
            if not isinstance(value, dict):
                raise StateConflictError("routed SSH keyscan targets are invalid")
            logical_id = value.get("logical_id")
            target = hosts.get(logical_id) if isinstance(logical_id, str) else None
            if (
                target is None
                or target.role is HostRole.JUMP_HOST
                or target.jump_host_id != jump.logical_id
                or target.route_mode != "proxy-jump"
                or target.ansible_host != target.private_address
            ):
                raise StateConflictError(
                    "routed SSH keyscan target conflicts with inventory routing"
                )
            expected.append(
                {
                    "address": target.private_address,
                    "logical_id": target.logical_id,
                    "port": 22,
                    "route_digest": routed_keyscan_route_digest(jump, target),
                }
            )
        if target_values != sorted(
            expected, key=lambda item: cast(str, item["logical_id"])
        ):
            raise StateConflictError(
                "routed SSH keyscan targets conflict with canonical inventory"
            )

    @staticmethod
    def _runtime_variables(
        name: str,
        inventory: StoredInventoryRecord,
        limit: tuple[str, ...],
    ) -> dict[str, object]:
        if name == "storage-discover":
            record = inventory.record
            return {
                "deploy_scylla_vms_cluster_uuid": str(record.cluster_uuid),
                "deploy_scylla_vms_host_manifest_digest": (
                    record.source_manifest_digest
                ),
                "deploy_scylla_vms_inventory_file_digest": inventory.digest,
                "deploy_scylla_vms_inventory_generation": record.generation,
                "deploy_scylla_vms_observation_digest": (record.source_manifest_digest),
                "deploy_scylla_vms_observation_generation": (
                    record.source_manifest_generation
                ),
            }
        if name != "inventory-preflight":
            return {}
        record = inventory.record
        return {
            "deploy_scylla_vms_cluster_uuid": str(record.cluster_uuid),
            "deploy_scylla_vms_inventory_digest": record.inventory_digest,
            "deploy_scylla_vms_expected_inventory_file_digest": inventory.digest,
            "deploy_scylla_vms_expected_inventory_generation": record.generation,
            "deploy_scylla_vms_expected_observation_digest": (
                record.source_manifest_digest
            ),
            "deploy_scylla_vms_expected_observation_generation": (
                record.source_manifest_generation
            ),
            "deploy_scylla_vms_expected_hosts": [
                {
                    "logical_id": host.logical_id,
                    "provider_id": host.provider_id,
                    "role": host.role.value,
                    "scylla_datacenter": host.scylla_datacenter,
                    "scylla_rack": host.scylla_rack,
                    "zone": host.zone,
                }
                for host in record.inventory.hosts
            ],
            "deploy_scylla_vms_operation_targets": list(limit),
        }

    def _require_toolchain(self) -> AnsibleToolchain:
        if self._toolchain is None:
            raise AnsibleError("Ansible toolchain version has not been validated")
        return self._toolchain

    @staticmethod
    def _validate_limit_membership(
        target_group: str,
        limit: tuple[str, ...],
        inventory: StoredInventoryRecord,
    ) -> None:
        host_ids = {host.logical_id for host in inventory.record.inventory.hosts}
        if not limit or not set(limit) <= host_ids:
            raise StateConflictError(
                "Ansible limit contains an unknown stable logical host ID"
            )
        if target_group != "all":
            groups = {
                group.name: set(group.hosts)
                for group in inventory.record.inventory.groups
            }
            allowed: set[str] = set()
            for group in target_group.split(":"):
                allowed.update(groups.get(group, set()))
            if not set(limit) <= allowed:
                raise StateConflictError(
                    "Ansible limit contains a host outside target groups"
                )

    @staticmethod
    def _validate_destination_probes(
        values: dict[str, object],
        inventory: StoredInventoryRecord,
        limit: tuple[str, ...],
    ) -> None:
        raw = values.get("deploy_scylla_vms_destination_probes", [])
        if not isinstance(raw, list):
            raise AnsibleError("Ansible destination probes are invalid")
        hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
        for item in raw:
            if not isinstance(item, dict):
                raise AnsibleError("Ansible destination probes are invalid")
            jump_id = item.get("jump_host_id")
            target_id = item.get("target_logical_id")
            jump = hosts.get(jump_id) if isinstance(jump_id, str) else None
            target = hosts.get(target_id) if isinstance(target_id, str) else None
            if (
                jump is None
                or jump.role.value != "jump-host"
                or jump.logical_id not in limit
                or target is None
                or target.role.value != item.get("role")
                or target.private_address != item.get("address")
                or target.public_address == item.get("address")
                or target.jump_host_id != jump.logical_id
                or target.route_mode != "proxy-jump"
            ):
                raise StateConflictError(
                    "Ansible destination probe conflicts with inventory routing"
                )

    def _write_extra_vars(self, values: dict[str, object]) -> Path:
        path = (
            self._builder.paths.ansible_local_tmp
            / f"extra-vars-{uuid.uuid4().hex}.json"
        )
        data = json.dumps(
            values,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(data)
            while remaining:
                written = os.write(descriptor, remaining)
                if written == 0:
                    raise AnsibleError("Ansible extra-vars write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        except OSError as error:
            raise AnsibleError(
                "Ansible extra-vars runtime file write failed"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        validate_state_file(path)
        return path

    @staticmethod
    def _protect_output(
        command: AnsibleCommand,
        inventory: StoredInventoryRecord,
        variables: dict[str, object] | None = None,
    ) -> AnsibleCommand:
        protected: set[str] = set(command.process.sensitive_values)
        logical_ids = {host.logical_id for host in inventory.record.inventory.hosts}
        protected.update(AnsibleService._inventory_protected_values(inventory))
        for value in (variables or {}).values():
            if isinstance(value, str):
                protected.add(value)
            elif isinstance(value, list):
                protected.update(
                    item
                    for item in value
                    if isinstance(item, str) and item not in logical_ids
                )
            elif isinstance(value, dict):
                protected.update(
                    item
                    for item in AnsibleService._nested_strings(value)
                    if item not in logical_ids
                    and (
                        len(item) >= 32
                        or item.startswith(("/dev/", "ocid1.", "sha256:"))
                    )
                )
        process = replace(
            command.process,
            sensitive_values=tuple(sorted(value for value in protected if value)),
        )
        return replace(command, process=process)

    @staticmethod
    def _nested_strings(value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list):
            return tuple(
                item
                for value_item in value
                for item in AnsibleService._nested_strings(value_item)
            )
        if isinstance(value, dict):
            return tuple(
                item
                for value_item in value.values()
                for item in AnsibleService._nested_strings(value_item)
            )
        return ()

    @staticmethod
    def _inventory_protected_values(
        inventory: StoredInventoryRecord,
    ) -> tuple[str, ...]:
        protected: set[str] = set()
        for host in inventory.record.inventory.hosts:
            protected.update(
                {
                    host.provider_id,
                    host.private_address,
                    host.ansible_host,
                    *(value for value in (host.public_address,) if value is not None),
                }
            )
        return tuple(sorted(value for value in protected if value))

    @staticmethod
    def _remove_runtime_file(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise AnsibleError("Ansible extra-vars runtime cleanup failed") from error

    def _run(
        self, command: AnsibleCommand, *, prerequisite: bool = False
    ) -> ProcessResult:
        try:
            return self._runner.run(command.process)
        except (ToolExecutionError, ToolPrerequisiteError) as error:
            if prerequisite:
                raise
            label = command.playbook or command.kind.value
            raise AnsibleError(f"Ansible {label} command failed") from error


def parse_inventory_preflight_evidence(
    stdout: str,
    inventory: StoredInventoryRecord,
    expected_hosts: tuple[str, ...],
    exit_code: int,
) -> InventoryPreflightEvidence:
    """Parse one exact preflight marker and recap; retain no inventory values."""

    if len(stdout.encode("utf-8")) > 262_144:
        raise AnsibleError("Ansible inventory preflight output exceeds the limit")
    markers: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_INVENTORY_PREFLIGHT_B64=" not in line:
            continue
        match = _INVENTORY_PREFLIGHT_MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible inventory preflight marker is malformed")
        try:
            raw = base64.b64decode(match.group("data"), validate=True)
            if len(raw) > 16 * 1024:
                raise AnsibleError("Ansible inventory preflight marker is oversized")
            value = json.loads(
                raw.decode("utf-8", errors="strict"),
                object_pairs_hook=_strict_result_object,
                parse_constant=_reject_result_constant,
            )
        except (binascii.Error, RecursionError, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible inventory preflight marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible inventory preflight result is malformed")
        markers.append(value)
    record = inventory.record
    expected: dict[str, object] = {
        "host_count": len(record.inventory.hosts),
        "inventory_file_digest": inventory.digest,
        "inventory_generation": record.generation,
        "observation_digest": record.source_manifest_digest,
        "observation_generation": record.source_manifest_generation,
        "schema_version": "deploy-scylla-vms.ansible-inventory-preflight/v1",
        "status": "passed",
        "target_count": len(expected_hosts),
    }
    if (exit_code == 0 and markers != [expected]) or (exit_code != 0 and markers):
        raise AnsibleError("Ansible inventory preflight result conflicts")
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible inventory preflight output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines()[1:]:
        if not line.strip():
            continue
        match = _RECAP_LINE.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible inventory preflight recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    if set(rows) != set(expected_hosts):
        raise AnsibleError("Ansible inventory preflight execution is incomplete")
    if exit_code == 0 and any(any(counts) for counts in rows.values()):
        raise AnsibleError("Ansible inventory preflight execution is incomplete")
    if exit_code == 2 and not any(failed for _, _, failed in rows.values()):
        raise AnsibleError("Ansible inventory preflight execution is incomplete")
    if exit_code == 4 and not any(unreachable for _, unreachable, _ in rows.values()):
        raise AnsibleError("Ansible inventory preflight execution is incomplete")
    if exit_code not in {0, 2, 4}:
        raise AnsibleError("Ansible inventory preflight execution is incomplete")
    status = (
        "passed" if exit_code == 0 else "unreachable" if exit_code == 4 else "failed"
    )
    return InventoryPreflightEvidence(
        status,
        len(record.inventory.hosts),
        len(expected_hosts),
        record.generation,
        inventory.digest,
        record.source_manifest_generation,
        record.source_manifest_digest,
    )


def _strict_result_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_result_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def parse_connectivity_evidence(
    stdout: str,
    expected_hosts: tuple[str, ...],
    exit_code: int,
    *,
    expected_probes: tuple[tuple[str, str, str, int], ...] = (),
) -> ConnectivityEvidence:
    """Parse only redacted per-host recap counts from connectivity output."""

    if len(stdout.encode("utf-8")) > 262_144:
        raise AnsibleError("Ansible connectivity output exceeds the evidence limit")
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible connectivity output omitted PLAY RECAP")
    hosts: list[HostConnectivityEvidence] = []
    lines = recap[2].splitlines()
    for line in lines[1:]:
        if not line.strip():
            continue
        match = _RECAP_LINE.fullmatch(line.strip())
        if match is None:
            raise AnsibleError("Ansible connectivity recap is malformed")
        logical_id = match.group("host")
        unreachable = int(match.group("unreachable"))
        failed = int(match.group("failed"))
        changed = int(match.group("changed"))
        if changed or (unreachable and failed):
            raise AnsibleError("Ansible connectivity recap contains invalid counts")
        host_status = (
            HostConnectivityStatus.UNREACHABLE
            if unreachable
            else HostConnectivityStatus.FAILED
            if failed
            else HostConnectivityStatus.REACHABLE
        )
        hosts.append(HostConnectivityEvidence(logical_id, host_status))
    ordered = tuple(sorted(hosts, key=lambda item: item.logical_id))
    if tuple(item.logical_id for item in ordered) != tuple(
        sorted(expected_hosts)
    ) or len(ordered) != len(expected_hosts):
        raise AnsibleError("Ansible connectivity recap membership conflicts")
    host_failures = sum(
        item.status is not HostConnectivityStatus.REACHABLE for item in ordered
    )
    if (exit_code == 0) != (host_failures == 0):
        raise AnsibleError("Ansible connectivity exit status conflicts with recap")
    host_statuses = {item.logical_id: item.status for item in ordered}
    parsed_probes: dict[tuple[str, str, str, int], DestinationProbeStatus] = {}
    for line in stdout.splitlines():
        if "DSV_TCP" not in line:
            continue
        match = _DESTINATION_EVIDENCE.search(line)
        if match is None:
            raise AnsibleError("Ansible destination evidence is malformed")
        key = (
            match.group("jump"),
            match.group("target"),
            match.group("role"),
            int(match.group("port")),
        )
        if key in parsed_probes:
            raise AnsibleError("Ansible destination evidence is duplicated")
        parsed_probes[key] = DestinationProbeStatus(match.group("status"))
    if set(parsed_probes) - set(expected_probes):
        raise AnsibleError("Ansible destination evidence membership conflicts")
    probes: list[DestinationProbeEvidence] = []
    for key in expected_probes:
        status = parsed_probes.get(key)
        if status is None:
            if host_statuses.get(key[0]) is HostConnectivityStatus.REACHABLE:
                raise AnsibleError("Ansible destination evidence is incomplete")
            status = DestinationProbeStatus.NOT_PERFORMED
        probes.append(DestinationProbeEvidence(*key, status))
    probe_failures = sum(
        item.status is not DestinationProbeStatus.PASSED for item in probes
    )
    failures = host_failures + probe_failures
    if not failures:
        overall_status = ConnectivityStatus.SUCCESS
    elif host_failures == len(ordered):
        overall_status = ConnectivityStatus.FAILURE
    else:
        overall_status = ConnectivityStatus.PARTIAL_FAILURE
    return ConnectivityEvidence(overall_status, ordered, tuple(probes))


def _probe_tuples(
    values: dict[str, object],
) -> tuple[tuple[str, str, str, int], ...]:
    raw = values.get("deploy_scylla_vms_destination_probes", [])
    if not isinstance(raw, list):
        return ()
    probes: list[tuple[str, str, str, int]] = []
    for item in raw:
        if not isinstance(item, dict):
            return ()
        jump = item.get("jump_host_id")
        target = item.get("target_logical_id")
        role = item.get("role")
        port = item.get("port")
        if (
            not isinstance(jump, str)
            or not isinstance(target, str)
            or not isinstance(role, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
        ):
            return ()
        probes.append((jump, target, role, port))
    return tuple(probes)
