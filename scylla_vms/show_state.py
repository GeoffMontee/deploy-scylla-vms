"""Strict non-mutating local-state loading for the show operation."""

import uuid
from dataclasses import dataclass

from scylla_vms.ansible.deploy_authorization import (
    DeployBaseOsAuthorizationStore,
    deploy_base_os_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_base_os_execution import (
    DeployBaseOsEvidenceStore,
    DeployBaseOsExecutionStore,
    deploy_base_os_evidence_id_from_filename,
    deploy_base_os_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciliationStore,
    deploy_base_os_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_final_routes import (
    DeployFinalRoutesEvidenceStore,
    DeployFinalRoutesExecutionStore,
    DeployPostFinalRoutesReconciliationStore,
    deploy_final_routes_evidence_id_from_filename,
    deploy_final_routes_execution_id_from_filename,
    deploy_post_final_routes_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_host_evidence import (
    DeployPreMutationEvidenceStore,
    DeployPreMutationExecutionStore,
    deploy_pre_mutation_evidence_id_from_filename,
    deploy_pre_mutation_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_host_reconciliation import (
    DeployHostEvidenceReconciliationStore,
    deploy_host_evidence_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_jump_host_authorization import (
    DeployJumpHostConfigureAuthorizationStore,
    deploy_jump_host_configure_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_jump_host_execution import (
    DeployJumpHostConfigureEvidenceStore,
    DeployJumpHostConfigureExecutionStore,
    deploy_jump_host_configure_evidence_id_from_filename,
    deploy_jump_host_configure_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    DeployPostJumpHostConfigureReconciliationStore,
    deploy_post_jump_host_configure_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_activation_plan import (
    DeployManagerActivationContextStore,
    DeployManagerActivationPlanStore,
    deploy_manager_activation_context_id_from_filename,
    deploy_manager_activation_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_agent_authorization import (
    DeployManagerAgentAuthorizationStore,
    deploy_manager_agent_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_agent_execution import (
    DeployManagerAgentEvidenceStore,
    DeployManagerAgentExecutionStore,
    deploy_manager_agent_evidence_id_from_filename,
    deploy_manager_agent_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_agent_reconciliation import (
    DeployPostManagerAgentReconciliationStore,
    deploy_post_manager_agent_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    DeployManagerBackendConfigurationContextStore,
    DeployManagerBackendConfigurationPlanStore,
    deploy_manager_backend_configuration_context_id_from_filename,
    deploy_manager_backend_configuration_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    DeployManagerBackendInstallationContextStore,
    DeployManagerBackendInstallationPlanStore,
    deploy_manager_backend_installation_context_id_from_filename,
    deploy_manager_backend_installation_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_authorization import (
    DeployManagerBackendLocalInstallAuthorizationStore,
    deploy_manager_backend_local_install_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_execution import (
    DeployManagerBackendLocalInstallEvidenceStore,
    DeployManagerBackendLocalInstallExecutionStore,
    deploy_manager_backend_local_install_evidence_id_from_filename,
    deploy_manager_backend_local_install_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    DeployPostManagerBackendLocalInstallReconciliationStore,
    deploy_post_manager_backend_local_install_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    DeployManagerBackendPreflightEvidenceStore,
    DeployManagerBackendPreflightExecutionStore,
    deploy_manager_backend_preflight_evidence_id_from_filename,
    deploy_manager_backend_preflight_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    DeployManagerBackendPreflightReconciliationStore,
    deploy_manager_backend_preflight_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    DeployManagerBackendStorageAllocationContextStore,
    DeployManagerBackendStorageAllocationPlanStore,
    deploy_manager_backend_storage_allocation_context_id_from_filename,
    deploy_manager_backend_storage_allocation_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_execution import (
    DeployManagerBackendStorageDiscoveryEvidenceStore,
    DeployManagerBackendStorageDiscoveryExecutionStore,
    deploy_manager_backend_storage_discovery_evidence_id_from_filename,
    deploy_manager_backend_storage_discovery_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_reconciliation import (
    DeployManagerBackendStorageDiscoveryReconciliationStore,
    deploy_manager_backend_storage_discovery_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_execution import (
    DeployManagerBackendStoragePreflightEvidenceStore,
    DeployManagerBackendStoragePreflightExecutionStore,
    deploy_manager_backend_storage_preflight_evidence_id_from_filename,
    deploy_manager_backend_storage_preflight_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_plan import (
    DeployManagerBackendStoragePreflightContextStore,
    DeployManagerBackendStoragePreflightPlanStore,
    deploy_manager_backend_storage_preflight_context_id_from_filename,
    deploy_manager_backend_storage_preflight_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_reconciliation import (
    DeployManagerBackendStoragePreflightReconciliationStore,
    deploy_manager_backend_storage_preflight_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_backend_storage_prepare_authorization import (
    DeployManagerBackendStoragePrepareAuthorizationStore,
    deploy_manager_backend_storage_prepare_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_server_authorization import (
    DeployManagerServerAuthorizationStore,
    deploy_manager_server_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_server_execution import (
    DeployManagerServerEvidenceStore,
    DeployManagerServerExecutionStore,
    deploy_manager_server_evidence_id_from_filename,
    deploy_manager_server_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    DeployPostManagerServerReconciliationStore,
    deploy_post_manager_server_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_agent_authorization import (
    DeployMonitoringAgentAuthorizationStore,
    deploy_monitoring_agent_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_agent_execution import (
    DeployMonitoringAgentEvidenceStore,
    DeployMonitoringAgentExecutionStore,
    deploy_monitoring_agent_evidence_id_from_filename,
    deploy_monitoring_agent_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    DeployPostMonitoringAgentReconciliationStore,
    deploy_post_monitoring_agent_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_stack_authorization import (
    DeployMonitoringStackAuthorizationStore,
    deploy_monitoring_stack_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_stack_execution import (
    DeployMonitoringStackEvidenceStore,
    DeployMonitoringStackExecutionStore,
    deploy_monitoring_stack_evidence_id_from_filename,
    deploy_monitoring_stack_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    DeployPostMonitoringStackReconciliationStore,
    deploy_post_monitoring_stack_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_targets_authorization import (
    DeployMonitoringTargetsAuthorizationStore,
    deploy_monitoring_targets_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_targets_execution import (
    DeployMonitoringTargetsEvidenceStore,
    DeployMonitoringTargetsExecutionStore,
    deploy_monitoring_targets_evidence_id_from_filename,
    deploy_monitoring_targets_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_monitoring_targets_reconciliation import (
    DeployPostMonitoringTargetsReconciliationStore,
    deploy_post_monitoring_targets_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_non_jump_base_os_authorization import (
    DeployNonJumpBaseOsAuthorizationStore,
    deploy_non_jump_base_os_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    DeployNonJumpBaseOsEvidenceStore,
    DeployNonJumpBaseOsExecutionStore,
    deploy_non_jump_base_os_evidence_id_from_filename,
    deploy_non_jump_base_os_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    DeployPostNonJumpBaseOsReconciliationStore,
    deploy_post_non_jump_base_os_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_non_jump_reboot_authorization import (
    DeployNonJumpRebootAuthorizationStore,
    DeployNonJumpRebootPlanStore,
    deploy_non_jump_reboot_authorization_id_from_filename,
    deploy_non_jump_reboot_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_non_jump_reboot_execution import (
    DeployNonJumpRebootEvidenceStore,
    DeployNonJumpRebootExecutionStore,
    deploy_non_jump_reboot_evidence_id_from_filename,
    deploy_non_jump_reboot_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_non_jump_reboot_reconciliation import (
    DeployPostNonJumpRebootReconciliationStore,
    deploy_post_non_jump_reboot_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_plan import (
    DeployAnsibleContextStore,
    DeployAnsiblePlanStore,
    deploy_ansible_context_id_from_filename,
    deploy_ansible_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_prerequisites import (
    DeployPrerequisiteEvidenceStore,
    DeployPrerequisiteExecutionStore,
    deploy_prerequisite_evidence_id_from_filename,
    deploy_prerequisite_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_reboot_authorization import (
    DeployRebootAuthorizationStore,
    DeployRebootPlanStore,
    deploy_reboot_authorization_id_from_filename,
    deploy_reboot_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_reboot_execution import (
    DeployRebootEvidenceStore,
    DeployRebootExecutionStore,
    deploy_reboot_evidence_id_from_filename,
    deploy_reboot_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    DeployPostRebootReconciliationStore,
    deploy_post_reboot_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_reconciliation import (
    DeployEffectivePlanStore,
    deploy_effective_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_authorization import (
    DeployScyllaBootstrapAuthorizationStore,
    deploy_scylla_bootstrap_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_execution import (
    DeployScyllaBootstrapEvidenceStore,
    DeployScyllaBootstrapExecutionStore,
    deploy_scylla_bootstrap_evidence_id_from_filename,
    deploy_scylla_bootstrap_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    DeployScyllaBootstrapContextStore,
    DeployScyllaBootstrapPlanStore,
    deploy_scylla_bootstrap_context_id_from_filename,
    deploy_scylla_bootstrap_plan_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import (
    DeployScyllaConfigureAuthorizationStore,
    deploy_scylla_configure_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_configure_execution import (
    DeployScyllaConfigureEvidenceStore,
    DeployScyllaConfigureExecutionStore,
    deploy_scylla_configure_evidence_id_from_filename,
    deploy_scylla_configure_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    DeployPostScyllaConfigureReconciliationStore,
    deploy_post_scylla_configure_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    DeployScyllaHealthCheckpointStore,
    DeployScyllaHealthEvidenceStore,
    DeployScyllaHealthExecutionStore,
    deploy_scylla_health_checkpoint_id_from_filename,
    deploy_scylla_health_evidence_id_from_filename,
    deploy_scylla_health_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_install_authorization import (
    DeployScyllaInstallAuthorizationStore,
    deploy_scylla_install_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_install_execution import (
    DeployScyllaInstallEvidenceStore,
    DeployScyllaInstallExecutionStore,
    deploy_scylla_install_evidence_id_from_filename,
    deploy_scylla_install_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    DeployPostScyllaInstallReconciliationStore,
    deploy_post_scylla_install_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_join_authorization import (
    DeployScyllaJoinAuthorizationStore,
    deploy_scylla_join_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_join_execution import (
    DeployScyllaJoinEvidenceStore,
    DeployScyllaJoinExecutionStore,
    deploy_scylla_join_evidence_id_from_filename,
    deploy_scylla_join_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    DeployScyllaJoinSafetyContextStore,
    DeployScyllaJoinSafetyEvidenceStore,
    DeployScyllaJoinSafetyReconciliationStore,
    deploy_scylla_join_safety_context_id_from_filename,
    deploy_scylla_join_safety_evidence_id_from_filename,
    deploy_scylla_join_safety_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_later_join_authorization import (
    DeployScyllaLaterJoinAuthorizationStore,
    deploy_scylla_later_join_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_later_join_execution import (
    DeployScyllaLaterJoinEvidenceStore,
    DeployScyllaLaterJoinExecutionStore,
    deploy_scylla_later_join_evidence_id_from_filename,
    deploy_scylla_later_join_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    DeployScyllaLaterJoinSafetyContextStore,
    DeployScyllaLaterJoinSafetyEvidenceStore,
    DeployScyllaLaterJoinSafetyReconciliationStore,
    deploy_scylla_later_join_safety_context_id_from_filename,
    deploy_scylla_later_join_safety_evidence_id_from_filename,
    deploy_scylla_later_join_safety_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_post_bootstrap_reconciliation import (
    DeployPostBootstrapReconciliationStore,
    deploy_scylla_post_bootstrap_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_post_join_health import (
    DeployScyllaPostJoinHealthEvidenceStore,
    DeployScyllaPostJoinHealthExecutionStore,
    DeployScyllaPostJoinHealthReconciliationStore,
    deploy_scylla_post_join_health_evidence_id_from_filename,
    deploy_scylla_post_join_health_execution_id_from_filename,
    deploy_scylla_post_join_health_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_post_later_join_health import (
    DeployScyllaPostLaterJoinHealthEvidenceStore,
    DeployScyllaPostLaterJoinHealthExecutionStore,
    DeployScyllaPostLaterJoinHealthReconciliationStore,
    deploy_scylla_post_later_join_health_evidence_id_from_filename,
    deploy_scylla_post_later_join_health_execution_id_from_filename,
    deploy_scylla_post_later_join_health_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_post_sequence_three_join_health import (
    DeployScyllaPostSequenceThreeHealthEvidenceStore,
    DeployScyllaPostSequenceThreeHealthExecutionStore,
    DeployScyllaPostSequenceThreeHealthReconciliationStore,
    deploy_scylla_post_sequence_three_health_evidence_id_from_filename,
    deploy_scylla_post_sequence_three_health_execution_id_from_filename,
    deploy_scylla_post_sequence_three_health_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    DeployScyllaSequenceThreeJoinAuthorizationStore,
    deploy_scylla_sequence_three_join_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    DeployScyllaSequenceThreeJoinEvidenceStore,
    DeployScyllaSequenceThreeJoinExecutionStore,
    deploy_scylla_sequence_three_join_evidence_id_from_filename,
    deploy_scylla_sequence_three_join_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    DeployScyllaSequenceThreeSafetyContextStore,
    DeployScyllaSequenceThreeSafetyEvidenceStore,
    DeployScyllaSequenceThreeSafetyReconciliationStore,
    deploy_scylla_sequence_three_safety_context_id_from_filename,
    deploy_scylla_sequence_three_safety_evidence_id_from_filename,
    deploy_scylla_sequence_three_safety_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_storage_discovery import (
    DeployPostStorageDiscoveryReconciliationStore,
    DeployStorageDiscoveryEvidenceStore,
    DeployStorageDiscoveryExecutionStore,
    deploy_post_storage_discovery_reconciliation_id_from_filename,
    deploy_storage_discovery_evidence_id_from_filename,
    deploy_storage_discovery_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_storage_postcheck import (
    DeployPostStoragePostcheckReconciliationStore,
    DeployStoragePostcheckEvidenceStore,
    DeployStoragePostcheckExecutionStore,
    deploy_post_storage_postcheck_reconciliation_id_from_filename,
    deploy_storage_postcheck_evidence_id_from_filename,
    deploy_storage_postcheck_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_storage_preflight import (
    DeployPostStoragePreflightReconciliationStore,
    DeployStoragePreflightEvidenceStore,
    DeployStoragePreflightExecutionStore,
    deploy_post_storage_preflight_reconciliation_id_from_filename,
    deploy_storage_preflight_evidence_id_from_filename,
    deploy_storage_preflight_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_storage_prepare_authorization import (
    DeployStoragePrepareAuthorizationStore,
    deploy_storage_prepare_authorization_id_from_filename,
)
from scylla_vms.ansible.deploy_storage_prepare_execution import (
    DeployStoragePrepareEvidenceStore,
    DeployStoragePrepareExecutionStore,
    deploy_storage_prepare_evidence_id_from_filename,
    deploy_storage_prepare_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    DeployPostStoragePrepareReconciliationStore,
    deploy_post_storage_prepare_reconciliation_id_from_filename,
)
from scylla_vms.ansible.operation_authorization import (
    OperationAuthorizationStore,
    operation_authorization_id_from_filename,
)
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    operation_plan_binding_id_from_filename,
)
from scylla_vms.ansible.operation_context import (
    OperationContextStore,
    operation_context_id_from_filename,
)
from scylla_vms.ansible.operation_evidence import (
    OperationEvidenceStore,
    operation_evidence_id_from_filename,
)
from scylla_vms.ansible.operation_execution import (
    OperationExecutionStore,
    operation_execution_id_from_filename,
)
from scylla_vms.ansible.operation_finalization import (
    OperationFinalizationStore,
    operation_finalization_id_from_filename,
)
from scylla_vms.ansible.readiness import ReadinessReport, build_readiness_report
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.desired import resolve_existing_config
from scylla_vms.errors import StateConflictError, StatePersistenceError
from scylla_vms.inventory import InventoryStore, StoredInventoryRecord
from scylla_vms.journal import OperationJournalStore, StoredOperationRecord
from scylla_vms.locking import ClusterReadLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.persistence import ClusterMetadataStore, StoredClusterMetadata
from scylla_vms.reconciliation import ReconciliationReport, reconcile_desired_observed
from scylla_vms.state import (
    refuse_unexpected_terraform_state,
    validate_state_directory,
    validate_state_file,
)


@dataclass(frozen=True, slots=True)
class LocalShowState:
    """Validated local sources captured under the cluster read lock."""

    cluster: StoredClusterMetadata
    latest_operation: StoredOperationRecord | None
    observed: StoredObservedState | None
    inventory: StoredInventoryRecord | None
    trust: StoredTrustRecord | None
    readiness: ReadinessReport
    reconciliation: ReconciliationReport


def load_local_show_state(
    request: OperationRequest, lock: ClusterReadLock
) -> LocalShowState:
    """Load canonical metadata and journals without writing or external access."""

    if request.operation.name != "show":
        raise StatePersistenceError("local show state requires a show request")
    lock.assert_held_for(request.paths)
    refuse_unexpected_terraform_state(request.paths, (request.paths.cluster_root,))
    cluster = ClusterMetadataStore(request.paths).read(
        expected_cluster_name=request.cluster_name,
        expected_provider=request.provider.name,
    )
    resolve_existing_config(request, cluster.record.desired_spec)
    observed = _load_observed(request, cluster)
    inventory = _load_inventory(request, cluster)
    trust, trust_conflict = _load_trust(request, cluster, inventory)
    latest = _load_latest_operation(request, cluster, lock)
    reconciliation = reconcile_desired_observed(
        cluster.record.desired_spec,
        observed.record.manifest if observed is not None else None,
    )
    readiness = build_readiness_report(
        observed, inventory, trust, trust_conflict=trust_conflict
    )
    return LocalShowState(
        cluster, latest, observed, inventory, trust, readiness, reconciliation
    )


def _load_observed(
    request: OperationRequest, cluster: StoredClusterMetadata
) -> StoredObservedState | None:
    validate_state_file(request.paths.terraform_observed, allow_missing=True)
    if not request.paths.terraform_observed.exists():
        return None
    return ObservedStateStore(request.paths).read(
        expected_cluster_uuid=cluster.record.cluster_uuid,
        expected_cluster_name=cluster.record.cluster_name,
        expected_provider=cluster.record.provider,
    )


def _load_inventory(
    request: OperationRequest, cluster: StoredClusterMetadata
) -> StoredInventoryRecord | None:
    validate_state_file(request.paths.ansible_inventory, allow_missing=True)
    if not request.paths.ansible_inventory.exists():
        return None
    return InventoryStore(request.paths).read(
        expected_cluster_uuid=cluster.record.cluster_uuid,
        expected_cluster_name=cluster.record.cluster_name,
        expected_provider=cluster.record.provider,
    )


def _load_trust(
    request: OperationRequest,
    cluster: StoredClusterMetadata,
    inventory: StoredInventoryRecord | None,
) -> tuple[StoredTrustRecord | None, bool]:
    validate_state_file(request.paths.ansible_trust, allow_missing=True)
    if not request.paths.ansible_trust.exists():
        return None, False
    stored = TrustStore(request.paths).read(
        expected_cluster_uuid=cluster.record.cluster_uuid,
        expected_cluster_name=cluster.record.cluster_name,
        expected_provider=cluster.record.provider,
    )
    if inventory is None:
        return stored, True
    try:
        TrustStore(request.paths).validate_runtime(stored, inventory)
    except (StateConflictError, StatePersistenceError):
        return stored, True
    return stored, False


def _load_latest_operation(
    request: OperationRequest,
    cluster: StoredClusterMetadata,
    lock: ClusterReadLock,
) -> StoredOperationRecord | None:
    validate_state_directory(request.paths.operations)
    records: list[StoredOperationRecord] = []
    try:
        entries = tuple(
            sorted(request.paths.operations.iterdir(), key=lambda item: item.name)
        )
    except OSError as error:
        raise StatePersistenceError("cannot safely list operation journals") from error
    for entry in entries:
        validate_state_file(entry)
        deploy_authorization_identifier = deploy_base_os_authorization_id_from_filename(
            entry.name
        )
        if deploy_authorization_identifier is not None:
            DeployBaseOsAuthorizationStore(
                request.paths, deploy_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        base_os_execution_identifier = deploy_base_os_execution_id_from_filename(
            entry.name
        )
        if base_os_execution_identifier is not None:
            DeployBaseOsExecutionStore(
                request.paths, base_os_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        base_os_evidence_identifier = deploy_base_os_evidence_id_from_filename(
            entry.name
        )
        if base_os_evidence_identifier is not None:
            DeployBaseOsEvidenceStore(request.paths, base_os_evidence_identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        base_os_reconciliation_identifier = (
            deploy_base_os_reconciliation_id_from_filename(entry.name)
        )
        if base_os_reconciliation_identifier is not None:
            DeployBaseOsReconciliationStore(
                request.paths, base_os_reconciliation_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        reboot_plan_identifier = deploy_reboot_plan_id_from_filename(entry.name)
        if reboot_plan_identifier is not None:
            DeployRebootPlanStore(request.paths, reboot_plan_identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        reboot_authorization_identifier = deploy_reboot_authorization_id_from_filename(
            entry.name
        )
        if reboot_authorization_identifier is not None:
            DeployRebootAuthorizationStore(
                request.paths, reboot_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        reboot_execution_identifier = deploy_reboot_execution_id_from_filename(
            entry.name
        )
        if reboot_execution_identifier is not None:
            DeployRebootExecutionStore(request.paths, reboot_execution_identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        reboot_evidence_identifier = deploy_reboot_evidence_id_from_filename(entry.name)
        if reboot_evidence_identifier is not None:
            DeployRebootEvidenceStore(request.paths, reboot_evidence_identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_reboot_identifier = deploy_post_reboot_reconciliation_id_from_filename(
            entry.name
        )
        if post_reboot_identifier is not None:
            DeployPostRebootReconciliationStore(
                request.paths, post_reboot_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        jump_host_authorization_identifier = (
            deploy_jump_host_configure_authorization_id_from_filename(entry.name)
        )
        if jump_host_authorization_identifier is not None:
            DeployJumpHostConfigureAuthorizationStore(
                request.paths, jump_host_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        jump_host_execution_identifier = (
            deploy_jump_host_configure_execution_id_from_filename(entry.name)
        )
        if jump_host_execution_identifier is not None:
            DeployJumpHostConfigureExecutionStore(
                request.paths, jump_host_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        jump_host_evidence_identifier = (
            deploy_jump_host_configure_evidence_id_from_filename(entry.name)
        )
        if jump_host_evidence_identifier is not None:
            DeployJumpHostConfigureEvidenceStore(
                request.paths, jump_host_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_jump_host_identifier = (
            deploy_post_jump_host_configure_reconciliation_id_from_filename(entry.name)
        )
        if post_jump_host_identifier is not None:
            DeployPostJumpHostConfigureReconciliationStore(
                request.paths, post_jump_host_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        final_routes_execution_identifier = (
            deploy_final_routes_execution_id_from_filename(entry.name)
        )
        if final_routes_execution_identifier is not None:
            DeployFinalRoutesExecutionStore(
                request.paths, final_routes_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        final_routes_evidence_identifier = (
            deploy_final_routes_evidence_id_from_filename(entry.name)
        )
        if final_routes_evidence_identifier is not None:
            DeployFinalRoutesEvidenceStore(
                request.paths, final_routes_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_final_routes_identifier = (
            deploy_post_final_routes_reconciliation_id_from_filename(entry.name)
        )
        if post_final_routes_identifier is not None:
            DeployPostFinalRoutesReconciliationStore(
                request.paths, post_final_routes_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        non_jump_base_os_authorization_identifier = (
            deploy_non_jump_base_os_authorization_id_from_filename(entry.name)
        )
        if non_jump_base_os_authorization_identifier is not None:
            DeployNonJumpBaseOsAuthorizationStore(
                request.paths, non_jump_base_os_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        non_jump_base_os_execution_identifier = (
            deploy_non_jump_base_os_execution_id_from_filename(entry.name)
        )
        if non_jump_base_os_execution_identifier is not None:
            DeployNonJumpBaseOsExecutionStore(
                request.paths, non_jump_base_os_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        non_jump_base_os_evidence_identifier = (
            deploy_non_jump_base_os_evidence_id_from_filename(entry.name)
        )
        if non_jump_base_os_evidence_identifier is not None:
            DeployNonJumpBaseOsEvidenceStore(
                request.paths, non_jump_base_os_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_non_jump_base_os_identifier = (
            deploy_post_non_jump_base_os_reconciliation_id_from_filename(entry.name)
        )
        if post_non_jump_base_os_identifier is not None:
            DeployPostNonJumpBaseOsReconciliationStore(
                request.paths, post_non_jump_base_os_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        non_jump_reboot_plan_identifier = deploy_non_jump_reboot_plan_id_from_filename(
            entry.name
        )
        if non_jump_reboot_plan_identifier is not None:
            DeployNonJumpRebootPlanStore(
                request.paths, non_jump_reboot_plan_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        non_jump_reboot_authorization_identifier = (
            deploy_non_jump_reboot_authorization_id_from_filename(entry.name)
        )
        if non_jump_reboot_authorization_identifier is not None:
            DeployNonJumpRebootAuthorizationStore(
                request.paths, non_jump_reboot_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        non_jump_reboot_execution_identifier = (
            deploy_non_jump_reboot_execution_id_from_filename(entry.name)
        )
        if non_jump_reboot_execution_identifier is not None:
            DeployNonJumpRebootExecutionStore(
                request.paths, non_jump_reboot_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        non_jump_reboot_evidence_identifier = (
            deploy_non_jump_reboot_evidence_id_from_filename(entry.name)
        )
        if non_jump_reboot_evidence_identifier is not None:
            DeployNonJumpRebootEvidenceStore(
                request.paths, non_jump_reboot_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_non_jump_reboot_identifier = (
            deploy_post_non_jump_reboot_reconciliation_id_from_filename(entry.name)
        )
        if post_non_jump_reboot_identifier is not None:
            DeployPostNonJumpRebootReconciliationStore(
                request.paths, post_non_jump_reboot_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_discovery_execution_identifier = (
            deploy_storage_discovery_execution_id_from_filename(entry.name)
        )
        if storage_discovery_execution_identifier is not None:
            DeployStorageDiscoveryExecutionStore(
                request.paths, storage_discovery_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_discovery_evidence_identifier = (
            deploy_storage_discovery_evidence_id_from_filename(entry.name)
        )
        if storage_discovery_evidence_identifier is not None:
            DeployStorageDiscoveryEvidenceStore(
                request.paths, storage_discovery_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_storage_discovery_identifier = (
            deploy_post_storage_discovery_reconciliation_id_from_filename(entry.name)
        )
        if post_storage_discovery_identifier is not None:
            DeployPostStorageDiscoveryReconciliationStore(
                request.paths, post_storage_discovery_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_preflight_execution_identifier = (
            deploy_storage_preflight_execution_id_from_filename(entry.name)
        )
        if storage_preflight_execution_identifier is not None:
            DeployStoragePreflightExecutionStore(
                request.paths, storage_preflight_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_preflight_evidence_identifier = (
            deploy_storage_preflight_evidence_id_from_filename(entry.name)
        )
        if storage_preflight_evidence_identifier is not None:
            DeployStoragePreflightEvidenceStore(
                request.paths, storage_preflight_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_storage_preflight_identifier = (
            deploy_post_storage_preflight_reconciliation_id_from_filename(entry.name)
        )
        if post_storage_preflight_identifier is not None:
            DeployPostStoragePreflightReconciliationStore(
                request.paths, post_storage_preflight_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_prepare_authorization_identifier = (
            deploy_storage_prepare_authorization_id_from_filename(entry.name)
        )
        if storage_prepare_authorization_identifier is not None:
            DeployStoragePrepareAuthorizationStore(
                request.paths, storage_prepare_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_prepare_execution_identifier = (
            deploy_storage_prepare_execution_id_from_filename(entry.name)
        )
        if storage_prepare_execution_identifier is not None:
            DeployStoragePrepareExecutionStore(
                request.paths, storage_prepare_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_prepare_evidence_identifier = (
            deploy_storage_prepare_evidence_id_from_filename(entry.name)
        )
        if storage_prepare_evidence_identifier is not None:
            DeployStoragePrepareEvidenceStore(
                request.paths, storage_prepare_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_storage_prepare_identifier = (
            deploy_post_storage_prepare_reconciliation_id_from_filename(entry.name)
        )
        if post_storage_prepare_identifier is not None:
            DeployPostStoragePrepareReconciliationStore(
                request.paths, post_storage_prepare_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_postcheck_execution_identifier = (
            deploy_storage_postcheck_execution_id_from_filename(entry.name)
        )
        if storage_postcheck_execution_identifier is not None:
            DeployStoragePostcheckExecutionStore(
                request.paths, storage_postcheck_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        storage_postcheck_evidence_identifier = (
            deploy_storage_postcheck_evidence_id_from_filename(entry.name)
        )
        if storage_postcheck_evidence_identifier is not None:
            DeployStoragePostcheckEvidenceStore(
                request.paths, storage_postcheck_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_storage_postcheck_identifier = (
            deploy_post_storage_postcheck_reconciliation_id_from_filename(entry.name)
        )
        if post_storage_postcheck_identifier is not None:
            DeployPostStoragePostcheckReconciliationStore(
                request.paths, post_storage_postcheck_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_install_authorization_identifier = (
            deploy_scylla_install_authorization_id_from_filename(entry.name)
        )
        if scylla_install_authorization_identifier is not None:
            DeployScyllaInstallAuthorizationStore(
                request.paths, scylla_install_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_install_execution_identifier = (
            deploy_scylla_install_execution_id_from_filename(entry.name)
        )
        if scylla_install_execution_identifier is not None:
            DeployScyllaInstallExecutionStore(
                request.paths, scylla_install_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_install_evidence_identifier = (
            deploy_scylla_install_evidence_id_from_filename(entry.name)
        )
        if scylla_install_evidence_identifier is not None:
            DeployScyllaInstallEvidenceStore(
                request.paths, scylla_install_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_scylla_install_identifier = (
            deploy_post_scylla_install_reconciliation_id_from_filename(entry.name)
        )
        if post_scylla_install_identifier is not None:
            DeployPostScyllaInstallReconciliationStore(
                request.paths, post_scylla_install_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_configure_authorization_identifier = (
            deploy_scylla_configure_authorization_id_from_filename(entry.name)
        )
        if scylla_configure_authorization_identifier is not None:
            DeployScyllaConfigureAuthorizationStore(
                request.paths, scylla_configure_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_configure_execution_identifier = (
            deploy_scylla_configure_execution_id_from_filename(entry.name)
        )
        if scylla_configure_execution_identifier is not None:
            DeployScyllaConfigureExecutionStore(
                request.paths, scylla_configure_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_configure_evidence_identifier = (
            deploy_scylla_configure_evidence_id_from_filename(entry.name)
        )
        if scylla_configure_evidence_identifier is not None:
            DeployScyllaConfigureEvidenceStore(
                request.paths, scylla_configure_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_scylla_configure_identifier = (
            deploy_post_scylla_configure_reconciliation_id_from_filename(entry.name)
        )
        if post_scylla_configure_identifier is not None:
            DeployPostScyllaConfigureReconciliationStore(
                request.paths, post_scylla_configure_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_bootstrap_identifier = (
            deploy_scylla_post_bootstrap_reconciliation_id_from_filename(entry.name)
        )
        if post_bootstrap_identifier is not None:
            DeployPostBootstrapReconciliationStore(
                request.paths, post_bootstrap_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_server_authorization_identifier = (
            deploy_manager_server_authorization_id_from_filename(entry.name)
        )
        if manager_server_authorization_identifier is not None:
            DeployManagerServerAuthorizationStore(
                request.paths, manager_server_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_server_execution_identifier = (
            deploy_manager_server_execution_id_from_filename(entry.name)
        )
        if manager_server_execution_identifier is not None:
            DeployManagerServerExecutionStore(
                request.paths, manager_server_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_server_evidence_identifier = (
            deploy_manager_server_evidence_id_from_filename(entry.name)
        )
        if manager_server_evidence_identifier is not None:
            DeployManagerServerEvidenceStore(
                request.paths, manager_server_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_manager_server_identifier = (
            deploy_post_manager_server_reconciliation_id_from_filename(entry.name)
        )
        if post_manager_server_identifier is not None:
            DeployPostManagerServerReconciliationStore(
                request.paths, post_manager_server_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_stack_authorization_identifier = (
            deploy_monitoring_stack_authorization_id_from_filename(entry.name)
        )
        if monitoring_stack_authorization_identifier is not None:
            DeployMonitoringStackAuthorizationStore(
                request.paths, monitoring_stack_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_stack_execution_identifier = (
            deploy_monitoring_stack_execution_id_from_filename(entry.name)
        )
        if monitoring_stack_execution_identifier is not None:
            DeployMonitoringStackExecutionStore(
                request.paths, monitoring_stack_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_stack_evidence_identifier = (
            deploy_monitoring_stack_evidence_id_from_filename(entry.name)
        )
        if monitoring_stack_evidence_identifier is not None:
            DeployMonitoringStackEvidenceStore(
                request.paths, monitoring_stack_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_monitoring_stack_identifier = (
            deploy_post_monitoring_stack_reconciliation_id_from_filename(entry.name)
        )
        if post_monitoring_stack_identifier is not None:
            DeployPostMonitoringStackReconciliationStore(
                request.paths, post_monitoring_stack_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_agent_authorization_identifier = (
            deploy_manager_agent_authorization_id_from_filename(entry.name)
        )
        if manager_agent_authorization_identifier is not None:
            DeployManagerAgentAuthorizationStore(
                request.paths, manager_agent_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_agent_execution_identifier = (
            deploy_manager_agent_execution_id_from_filename(entry.name)
        )
        if manager_agent_execution_identifier is not None:
            DeployManagerAgentExecutionStore(
                request.paths, manager_agent_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_agent_evidence_identifier = (
            deploy_manager_agent_evidence_id_from_filename(entry.name)
        )
        if manager_agent_evidence_identifier is not None:
            DeployManagerAgentEvidenceStore(
                request.paths, manager_agent_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_manager_agent_identifier = (
            deploy_post_manager_agent_reconciliation_id_from_filename(entry.name)
        )
        if post_manager_agent_identifier is not None:
            DeployPostManagerAgentReconciliationStore(
                request.paths, post_manager_agent_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_agent_authorization_identifier = (
            deploy_monitoring_agent_authorization_id_from_filename(entry.name)
        )
        if monitoring_agent_authorization_identifier is not None:
            DeployMonitoringAgentAuthorizationStore(
                request.paths, monitoring_agent_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_agent_execution_identifier = (
            deploy_monitoring_agent_execution_id_from_filename(entry.name)
        )
        if monitoring_agent_execution_identifier is not None:
            DeployMonitoringAgentExecutionStore(
                request.paths, monitoring_agent_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_agent_evidence_identifier = (
            deploy_monitoring_agent_evidence_id_from_filename(entry.name)
        )
        if monitoring_agent_evidence_identifier is not None:
            DeployMonitoringAgentEvidenceStore(
                request.paths, monitoring_agent_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_monitoring_agent_identifier = (
            deploy_post_monitoring_agent_reconciliation_id_from_filename(entry.name)
        )
        if post_monitoring_agent_identifier is not None:
            DeployPostMonitoringAgentReconciliationStore(
                request.paths, post_monitoring_agent_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_targets_authorization_identifier = (
            deploy_monitoring_targets_authorization_id_from_filename(entry.name)
        )
        if monitoring_targets_authorization_identifier is not None:
            DeployMonitoringTargetsAuthorizationStore(
                request.paths, monitoring_targets_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_targets_execution_identifier = (
            deploy_monitoring_targets_execution_id_from_filename(entry.name)
        )
        if monitoring_targets_execution_identifier is not None:
            DeployMonitoringTargetsExecutionStore(
                request.paths, monitoring_targets_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        monitoring_targets_evidence_identifier = (
            deploy_monitoring_targets_evidence_id_from_filename(entry.name)
        )
        if monitoring_targets_evidence_identifier is not None:
            DeployMonitoringTargetsEvidenceStore(
                request.paths, monitoring_targets_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_monitoring_targets_identifier = (
            deploy_post_monitoring_targets_reconciliation_id_from_filename(entry.name)
        )
        if post_monitoring_targets_identifier is not None:
            DeployPostMonitoringTargetsReconciliationStore(
                request.paths, post_monitoring_targets_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_activation_context_identifier = (
            deploy_manager_activation_context_id_from_filename(entry.name)
        )
        if manager_activation_context_identifier is not None:
            DeployManagerActivationContextStore(
                request.paths, manager_activation_context_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_activation_plan_identifier = (
            deploy_manager_activation_plan_id_from_filename(entry.name)
        )
        if manager_activation_plan_identifier is not None:
            DeployManagerActivationPlanStore(
                request.paths, manager_activation_plan_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_context_identifier = (
            deploy_manager_backend_configuration_context_id_from_filename(entry.name)
        )
        if manager_backend_context_identifier is not None:
            DeployManagerBackendConfigurationContextStore(
                request.paths, manager_backend_context_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_plan_identifier = (
            deploy_manager_backend_configuration_plan_id_from_filename(entry.name)
        )
        if manager_backend_plan_identifier is not None:
            DeployManagerBackendConfigurationPlanStore(
                request.paths, manager_backend_plan_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_preflight_execution_identifier = (
            deploy_manager_backend_preflight_execution_id_from_filename(entry.name)
        )
        if manager_backend_preflight_execution_identifier is not None:
            DeployManagerBackendPreflightExecutionStore(
                request.paths, manager_backend_preflight_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_preflight_evidence_identifier = (
            deploy_manager_backend_preflight_evidence_id_from_filename(entry.name)
        )
        if manager_backend_preflight_evidence_identifier is not None:
            DeployManagerBackendPreflightEvidenceStore(
                request.paths, manager_backend_preflight_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_preflight_reconciliation_identifier = (
            deploy_manager_backend_preflight_reconciliation_id_from_filename(entry.name)
        )
        if manager_backend_preflight_reconciliation_identifier is not None:
            DeployManagerBackendPreflightReconciliationStore(
                request.paths, manager_backend_preflight_reconciliation_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_installation_context_identifier = (
            deploy_manager_backend_installation_context_id_from_filename(entry.name)
        )
        if manager_backend_installation_context_identifier is not None:
            DeployManagerBackendInstallationContextStore(
                request.paths, manager_backend_installation_context_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_installation_plan_identifier = (
            deploy_manager_backend_installation_plan_id_from_filename(entry.name)
        )
        if manager_backend_installation_plan_identifier is not None:
            DeployManagerBackendInstallationPlanStore(
                request.paths, manager_backend_installation_plan_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_local_install_authorization_identifier = (
            deploy_manager_backend_local_install_authorization_id_from_filename(
                entry.name
            )
        )
        if manager_backend_local_install_authorization_identifier is not None:
            DeployManagerBackendLocalInstallAuthorizationStore(
                request.paths,
                manager_backend_local_install_authorization_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_local_install_execution_identifier = (
            deploy_manager_backend_local_install_execution_id_from_filename(entry.name)
        )
        if manager_backend_local_install_execution_identifier is not None:
            DeployManagerBackendLocalInstallExecutionStore(
                request.paths,
                manager_backend_local_install_execution_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_local_install_evidence_identifier = (
            deploy_manager_backend_local_install_evidence_id_from_filename(entry.name)
        )
        if manager_backend_local_install_evidence_identifier is not None:
            DeployManagerBackendLocalInstallEvidenceStore(
                request.paths,
                manager_backend_local_install_evidence_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_local_install_reconciliation_identifier = (
            deploy_post_manager_backend_local_install_reconciliation_id_from_filename(
                entry.name
            )
        )
        if manager_backend_local_install_reconciliation_identifier is not None:
            DeployPostManagerBackendLocalInstallReconciliationStore(
                request.paths,
                manager_backend_local_install_reconciliation_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_context_identifier = (
            deploy_manager_backend_storage_allocation_context_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_context_identifier is not None:
            DeployManagerBackendStorageAllocationContextStore(
                request.paths,
                manager_backend_storage_context_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_plan_identifier = (
            deploy_manager_backend_storage_allocation_plan_id_from_filename(entry.name)
        )
        if manager_backend_storage_plan_identifier is not None:
            DeployManagerBackendStorageAllocationPlanStore(
                request.paths,
                manager_backend_storage_plan_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_execution_identifier = (
            deploy_manager_backend_storage_discovery_execution_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_execution_identifier is not None:
            DeployManagerBackendStorageDiscoveryExecutionStore(
                request.paths,
                manager_backend_storage_execution_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_evidence_identifier = (
            deploy_manager_backend_storage_discovery_evidence_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_evidence_identifier is not None:
            DeployManagerBackendStorageDiscoveryEvidenceStore(
                request.paths,
                manager_backend_storage_evidence_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_reconciliation_identifier = (
            deploy_manager_backend_storage_discovery_reconciliation_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_reconciliation_identifier is not None:
            DeployManagerBackendStorageDiscoveryReconciliationStore(
                request.paths,
                manager_backend_storage_reconciliation_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_preflight_context_identifier = (
            deploy_manager_backend_storage_preflight_context_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_preflight_context_identifier is not None:
            DeployManagerBackendStoragePreflightContextStore(
                request.paths,
                manager_backend_storage_preflight_context_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_preflight_plan_identifier = (
            deploy_manager_backend_storage_preflight_plan_id_from_filename(entry.name)
        )
        if manager_backend_storage_preflight_plan_identifier is not None:
            DeployManagerBackendStoragePreflightPlanStore(
                request.paths,
                manager_backend_storage_preflight_plan_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_preflight_execution_identifier = (
            deploy_manager_backend_storage_preflight_execution_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_preflight_execution_identifier is not None:
            DeployManagerBackendStoragePreflightExecutionStore(
                request.paths,
                manager_backend_storage_preflight_execution_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_preflight_evidence_identifier = (
            deploy_manager_backend_storage_preflight_evidence_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_preflight_evidence_identifier is not None:
            DeployManagerBackendStoragePreflightEvidenceStore(
                request.paths,
                manager_backend_storage_preflight_evidence_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_preflight_reconciliation_identifier = (
            deploy_manager_backend_storage_preflight_reconciliation_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_preflight_reconciliation_identifier is not None:
            DeployManagerBackendStoragePreflightReconciliationStore(
                request.paths,
                manager_backend_storage_preflight_reconciliation_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        manager_backend_storage_prepare_authorization_identifier = (
            deploy_manager_backend_storage_prepare_authorization_id_from_filename(
                entry.name
            )
        )
        if manager_backend_storage_prepare_authorization_identifier is not None:
            DeployManagerBackendStoragePrepareAuthorizationStore(
                request.paths,
                manager_backend_storage_prepare_authorization_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_bootstrap_context_identifier = (
            deploy_scylla_bootstrap_context_id_from_filename(entry.name)
        )
        if scylla_bootstrap_context_identifier is not None:
            DeployScyllaBootstrapContextStore(
                request.paths, scylla_bootstrap_context_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_bootstrap_plan_identifier = (
            deploy_scylla_bootstrap_plan_id_from_filename(entry.name)
        )
        if scylla_bootstrap_plan_identifier is not None:
            DeployScyllaBootstrapPlanStore(
                request.paths, scylla_bootstrap_plan_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_bootstrap_authorization_identifier = (
            deploy_scylla_bootstrap_authorization_id_from_filename(entry.name)
        )
        if scylla_bootstrap_authorization_identifier is not None:
            DeployScyllaBootstrapAuthorizationStore(
                request.paths, scylla_bootstrap_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_bootstrap_execution_identifier = (
            deploy_scylla_bootstrap_execution_id_from_filename(entry.name)
        )
        if scylla_bootstrap_execution_identifier is not None:
            DeployScyllaBootstrapExecutionStore(
                request.paths, scylla_bootstrap_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_bootstrap_evidence_identifier = (
            deploy_scylla_bootstrap_evidence_id_from_filename(entry.name)
        )
        if scylla_bootstrap_evidence_identifier is not None:
            DeployScyllaBootstrapEvidenceStore(
                request.paths, scylla_bootstrap_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_health_execution_identifier = (
            deploy_scylla_health_execution_id_from_filename(entry.name)
        )
        if scylla_health_execution_identifier is not None:
            DeployScyllaHealthExecutionStore(
                request.paths, scylla_health_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_health_evidence_identifier = (
            deploy_scylla_health_evidence_id_from_filename(entry.name)
        )
        if scylla_health_evidence_identifier is not None:
            DeployScyllaHealthEvidenceStore(
                request.paths, scylla_health_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_health_checkpoint_identifier = (
            deploy_scylla_health_checkpoint_id_from_filename(entry.name)
        )
        if scylla_health_checkpoint_identifier is not None:
            DeployScyllaHealthCheckpointStore(
                request.paths, scylla_health_checkpoint_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_join_safety_context_identifier = (
            deploy_scylla_join_safety_context_id_from_filename(entry.name)
        )
        if scylla_join_safety_context_identifier is not None:
            DeployScyllaJoinSafetyContextStore(
                request.paths, scylla_join_safety_context_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_join_safety_evidence_identifier = (
            deploy_scylla_join_safety_evidence_id_from_filename(entry.name)
        )
        if scylla_join_safety_evidence_identifier is not None:
            DeployScyllaJoinSafetyEvidenceStore(
                request.paths, scylla_join_safety_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_join_safety_reconciliation_identifier = (
            deploy_scylla_join_safety_reconciliation_id_from_filename(entry.name)
        )
        if scylla_join_safety_reconciliation_identifier is not None:
            DeployScyllaJoinSafetyReconciliationStore(
                request.paths, scylla_join_safety_reconciliation_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_join_authorization_identifier = (
            deploy_scylla_join_authorization_id_from_filename(entry.name)
        )
        if scylla_join_authorization_identifier is not None:
            DeployScyllaJoinAuthorizationStore(
                request.paths, scylla_join_authorization_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_join_execution_identifier = (
            deploy_scylla_join_execution_id_from_filename(entry.name)
        )
        if scylla_join_execution_identifier is not None:
            DeployScyllaJoinExecutionStore(
                request.paths, scylla_join_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_join_evidence_identifier = deploy_scylla_join_evidence_id_from_filename(
            entry.name
        )
        if scylla_join_evidence_identifier is not None:
            DeployScyllaJoinEvidenceStore(
                request.paths, scylla_join_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_post_join_health_execution_identifier = (
            deploy_scylla_post_join_health_execution_id_from_filename(entry.name)
        )
        if scylla_post_join_health_execution_identifier is not None:
            DeployScyllaPostJoinHealthExecutionStore(
                request.paths, scylla_post_join_health_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_post_join_health_evidence_identifier = (
            deploy_scylla_post_join_health_evidence_id_from_filename(entry.name)
        )
        if scylla_post_join_health_evidence_identifier is not None:
            DeployScyllaPostJoinHealthEvidenceStore(
                request.paths, scylla_post_join_health_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_post_join_health_reconciliation_identifier = (
            deploy_scylla_post_join_health_reconciliation_id_from_filename(entry.name)
        )
        if scylla_post_join_health_reconciliation_identifier is not None:
            DeployScyllaPostJoinHealthReconciliationStore(
                request.paths, scylla_post_join_health_reconciliation_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_sequence_three_safety_context_identifier = (
            deploy_scylla_sequence_three_safety_context_id_from_filename(entry.name)
        )
        if scylla_sequence_three_safety_context_identifier is not None:
            DeployScyllaSequenceThreeSafetyContextStore(
                request.paths, scylla_sequence_three_safety_context_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_sequence_three_safety_evidence_identifier = (
            deploy_scylla_sequence_three_safety_evidence_id_from_filename(entry.name)
        )
        if scylla_sequence_three_safety_evidence_identifier is not None:
            DeployScyllaSequenceThreeSafetyEvidenceStore(
                request.paths, scylla_sequence_three_safety_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_sequence_three_safety_reconciliation_identifier = (
            deploy_scylla_sequence_three_safety_reconciliation_id_from_filename(
                entry.name
            )
        )
        if scylla_sequence_three_safety_reconciliation_identifier is not None:
            DeployScyllaSequenceThreeSafetyReconciliationStore(
                request.paths,
                scylla_sequence_three_safety_reconciliation_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_sequence_three_join_authorization_identifier = (
            deploy_scylla_sequence_three_join_authorization_id_from_filename(entry.name)
        )
        if scylla_sequence_three_join_authorization_identifier is not None:
            DeployScyllaSequenceThreeJoinAuthorizationStore(
                request.paths,
                scylla_sequence_three_join_authorization_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_sequence_three_join_execution_identifier = (
            deploy_scylla_sequence_three_join_execution_id_from_filename(entry.name)
        )
        if scylla_sequence_three_join_execution_identifier is not None:
            DeployScyllaSequenceThreeJoinExecutionStore(
                request.paths,
                scylla_sequence_three_join_execution_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_sequence_three_join_evidence_identifier = (
            deploy_scylla_sequence_three_join_evidence_id_from_filename(entry.name)
        )
        if scylla_sequence_three_join_evidence_identifier is not None:
            DeployScyllaSequenceThreeJoinEvidenceStore(
                request.paths,
                scylla_sequence_three_join_evidence_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_post_sequence_three_health_execution_identifier = (
            deploy_scylla_post_sequence_three_health_execution_id_from_filename(
                entry.name
            )
        )
        if scylla_post_sequence_three_health_execution_identifier is not None:
            DeployScyllaPostSequenceThreeHealthExecutionStore(
                request.paths,
                scylla_post_sequence_three_health_execution_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_post_sequence_three_health_evidence_identifier = (
            deploy_scylla_post_sequence_three_health_evidence_id_from_filename(
                entry.name
            )
        )
        if scylla_post_sequence_three_health_evidence_identifier is not None:
            DeployScyllaPostSequenceThreeHealthEvidenceStore(
                request.paths,
                scylla_post_sequence_three_health_evidence_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_post_sequence_three_health_reconciliation_identifier = (
            deploy_scylla_post_sequence_three_health_reconciliation_id_from_filename(
                entry.name
            )
        )
        if scylla_post_sequence_three_health_reconciliation_identifier is not None:
            DeployScyllaPostSequenceThreeHealthReconciliationStore(
                request.paths,
                scylla_post_sequence_three_health_reconciliation_identifier,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_later_join_safety_context_identifier = (
            deploy_scylla_later_join_safety_context_id_from_filename(entry.name)
        )
        if scylla_later_join_safety_context_identifier is not None:
            operation_id, sequence = scylla_later_join_safety_context_identifier
            DeployScyllaLaterJoinSafetyContextStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_later_join_safety_evidence_identifier = (
            deploy_scylla_later_join_safety_evidence_id_from_filename(entry.name)
        )
        if scylla_later_join_safety_evidence_identifier is not None:
            operation_id, sequence = scylla_later_join_safety_evidence_identifier
            DeployScyllaLaterJoinSafetyEvidenceStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_later_join_safety_reconciliation_identifier = (
            deploy_scylla_later_join_safety_reconciliation_id_from_filename(entry.name)
        )
        if scylla_later_join_safety_reconciliation_identifier is not None:
            operation_id, sequence = scylla_later_join_safety_reconciliation_identifier
            DeployScyllaLaterJoinSafetyReconciliationStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_later_join_authorization_identifier = (
            deploy_scylla_later_join_authorization_id_from_filename(entry.name)
        )
        if scylla_later_join_authorization_identifier is not None:
            operation_id, sequence = scylla_later_join_authorization_identifier
            DeployScyllaLaterJoinAuthorizationStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_later_join_execution_identifier = (
            deploy_scylla_later_join_execution_id_from_filename(entry.name)
        )
        if scylla_later_join_execution_identifier is not None:
            operation_id, sequence = scylla_later_join_execution_identifier
            DeployScyllaLaterJoinExecutionStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        scylla_later_join_evidence_identifier = (
            deploy_scylla_later_join_evidence_id_from_filename(entry.name)
        )
        if scylla_later_join_evidence_identifier is not None:
            operation_id, sequence = scylla_later_join_evidence_identifier
            DeployScyllaLaterJoinEvidenceStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_later_join_health_execution_identifier = (
            deploy_scylla_post_later_join_health_execution_id_from_filename(entry.name)
        )
        if post_later_join_health_execution_identifier is not None:
            operation_id, sequence = post_later_join_health_execution_identifier
            DeployScyllaPostLaterJoinHealthExecutionStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_later_join_health_evidence_identifier = (
            deploy_scylla_post_later_join_health_evidence_id_from_filename(entry.name)
        )
        if post_later_join_health_evidence_identifier is not None:
            operation_id, sequence = post_later_join_health_evidence_identifier
            DeployScyllaPostLaterJoinHealthEvidenceStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        post_later_join_health_reconciliation_identifier = (
            deploy_scylla_post_later_join_health_reconciliation_id_from_filename(
                entry.name
            )
        )
        if post_later_join_health_reconciliation_identifier is not None:
            operation_id, sequence = post_later_join_health_reconciliation_identifier
            DeployScyllaPostLaterJoinHealthReconciliationStore(
                request.paths,
                operation_id,
                sequence,
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        deploy_context_identifier = deploy_ansible_context_id_from_filename(entry.name)
        if deploy_context_identifier is not None:
            DeployAnsibleContextStore(request.paths, deploy_context_identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        deploy_plan_identifier = deploy_ansible_plan_id_from_filename(entry.name)
        if deploy_plan_identifier is not None:
            DeployAnsiblePlanStore(request.paths, deploy_plan_identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        deploy_execution_identifier = deploy_prerequisite_execution_id_from_filename(
            entry.name
        )
        if deploy_execution_identifier is not None:
            DeployPrerequisiteExecutionStore(
                request.paths, deploy_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        deploy_evidence_identifier = deploy_prerequisite_evidence_id_from_filename(
            entry.name
        )
        if deploy_evidence_identifier is not None:
            DeployPrerequisiteEvidenceStore(
                request.paths, deploy_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        pre_mutation_execution_identifier = (
            deploy_pre_mutation_execution_id_from_filename(entry.name)
        )
        if pre_mutation_execution_identifier is not None:
            DeployPreMutationExecutionStore(
                request.paths, pre_mutation_execution_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        pre_mutation_evidence_identifier = (
            deploy_pre_mutation_evidence_id_from_filename(entry.name)
        )
        if pre_mutation_evidence_identifier is not None:
            DeployPreMutationEvidenceStore(
                request.paths, pre_mutation_evidence_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        host_reconciliation_identifier = (
            deploy_host_evidence_reconciliation_id_from_filename(entry.name)
        )
        if host_reconciliation_identifier is not None:
            DeployHostEvidenceReconciliationStore(
                request.paths, host_reconciliation_identifier
            ).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        effective_plan_identifier = deploy_effective_plan_id_from_filename(entry.name)
        if effective_plan_identifier is not None:
            DeployEffectivePlanStore(request.paths, effective_plan_identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        context_identifier = operation_context_id_from_filename(entry.name)
        if context_identifier is not None:
            OperationContextStore(request.paths, context_identifier).read_locked(
                lock,
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        evidence_identifier = operation_evidence_id_from_filename(entry.name)
        if evidence_identifier is not None:
            OperationEvidenceStore(request.paths, evidence_identifier).read_locked(
                lock,
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        execution_identifier = operation_execution_id_from_filename(entry.name)
        if execution_identifier is not None:
            OperationExecutionStore(request.paths, execution_identifier).read_locked(
                lock,
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        finalization_identifier = operation_finalization_id_from_filename(entry.name)
        if finalization_identifier is not None:
            OperationFinalizationStore(
                request.paths, finalization_identifier
            ).read_locked(
                lock,
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        authorization_identifier = operation_authorization_id_from_filename(entry.name)
        if authorization_identifier is not None:
            OperationAuthorizationStore(
                request.paths, authorization_identifier
            ).read_locked(
                lock,
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        binding_identifier = operation_plan_binding_id_from_filename(entry.name)
        if binding_identifier is not None:
            OperationPlanBindingStore(request.paths, binding_identifier).read_locked(
                lock,
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
            continue
        if entry.suffix != ".json":
            raise StatePersistenceError("operation journal filename is invalid")
        identifier_text = entry.stem
        try:
            identifier = uuid.UUID(identifier_text)
        except ValueError as error:
            raise StatePersistenceError(
                "operation journal filename is invalid"
            ) from error
        if str(identifier) != identifier_text:
            raise StatePersistenceError("operation journal filename is invalid")
        records.append(
            OperationJournalStore(request.paths, identifier).read(
                expected_cluster_uuid=cluster.record.cluster_uuid,
                expected_cluster_name=cluster.record.cluster_name,
            )
        )
    if not records:
        return None
    return max(
        records,
        key=lambda stored: (
            stored.record.updated_at,
            str(stored.record.operation_id),
        ),
    )
