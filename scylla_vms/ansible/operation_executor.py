"""Strict internal bridge from operation steps to the controlled Ansible service."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from typing import Protocol, cast

from scylla_vms.ansible.jump_host_configure import (
    parse_jump_host_configure_execution,
)
from scylla_vms.ansible.manager_agent import parse_manager_agent_execution
from scylla_vms.ansible.manager_server import parse_manager_server_execution
from scylla_vms.ansible.manager_tasks import parse_manager_tasks_execution
from scylla_vms.ansible.monitoring_agent import parse_monitoring_agent_execution
from scylla_vms.ansible.monitoring_stack import parse_monitoring_stack_execution
from scylla_vms.ansible.monitoring_targets import (
    parse_monitoring_targets_execution,
)
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    readiness_binding_digest,
)
from scylla_vms.ansible.operation_context import (
    OperationContextStore,
    StoredOperationContext,
    reconstruct_operation_context,
)
from scylla_vms.ansible.operation_evidence import (
    OperationEvidenceStore,
    operation_evidence_path,
    persist_operation_step_evidence,
    validate_operation_evidence_checkpoint,
    validate_operation_evidence_intents,
)
from scylla_vms.ansible.operation_execution import (
    ExecutionAttemptState,
    OperationExecutionStore,
    OperationStepExecution,
    OperationStepInterrupted,
    OperationStepMalformedResult,
    OperationStepTimedOut,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.os_reprovision_prepare import (
    parse_os_reprovision_prepare_execution,
)
from scylla_vms.ansible.os_upgrade_in_place import (
    parse_os_upgrade_in_place_execution,
)
from scylla_vms.ansible.os_upgrade_postcheck import (
    parse_os_upgrade_postcheck_execution,
)
from scylla_vms.ansible.os_upgrade_preflight import (
    parse_os_upgrade_preflight_execution,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import PlaybookDefinition
from scylla_vms.ansible.scylla_bootstrap import parse_scylla_bootstrap_execution
from scylla_vms.ansible.scylla_cleanup import parse_scylla_cleanup_execution
from scylla_vms.ansible.scylla_cluster_shutdown import (
    parse_scylla_cluster_shutdown_execution,
)
from scylla_vms.ansible.scylla_configure import parse_scylla_configure_execution
from scylla_vms.ansible.scylla_health import parse_scylla_health_execution
from scylla_vms.ansible.scylla_install import parse_scylla_install_execution
from scylla_vms.ansible.scylla_remove_dead import (
    parse_scylla_remove_dead_execution,
)
from scylla_vms.ansible.scylla_remove_live import (
    parse_scylla_remove_live_execution,
)
from scylla_vms.ansible.scylla_repair import parse_scylla_repair_execution
from scylla_vms.ansible.scylla_replace_dead import (
    parse_scylla_replace_dead_execution,
)
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
)
from scylla_vms.ansible.service_converge import (
    parse_service_converge_execution,
)
from scylla_vms.ansible.source import (
    load_ansible_source_bundle,
    validate_ansible_config,
)
from scylla_vms.ansible.storage_postcheck import (
    parse_storage_postcheck_execution,
)
from scylla_vms.ansible.storage_preflight import (
    parse_storage_preflight_projection,
)
from scylla_vms.ansible.storage_prepare import parse_storage_prepare_execution
from scylla_vms.ansible.storage_retire import parse_storage_retire_execution
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import InventoryStore, StoredInventoryRecord
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    digest_bytes,
    serialize_json,
)
from scylla_vms.process import ProcessOutputError, ProcessTimeoutError
from scylla_vms.state import StatePaths, validate_state_file

_ADAPTER_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-adapter-evidence/v1"
)
_NON_SUCCESS_STATUSES = frozenset(
    {
        "blocked",
        "failed",
        "failure",
        "not-performed",
        "not-ready",
        "partial",
        "partial-failure",
        "unavailable",
        "unsupported",
    }
)


class _ExpectedPayloadParser(Protocol):
    def __call__(
        self,
        stdout: str,
        *,
        expected_payload: dict[str, object],
        exit_code: int,
    ) -> object: ...


_EXPECTED_PAYLOAD_PARSERS: Mapping[str, _ExpectedPayloadParser] = {
    "jump-host-configure": parse_jump_host_configure_execution,
    "manager-agent": parse_manager_agent_execution,
    "manager-server": parse_manager_server_execution,
    "manager-tasks": parse_manager_tasks_execution,
    "monitoring-agent": parse_monitoring_agent_execution,
    "monitoring-stack": parse_monitoring_stack_execution,
    "monitoring-targets": parse_monitoring_targets_execution,
    "os-reprovision-prepare": parse_os_reprovision_prepare_execution,
    "os-upgrade-in-place": parse_os_upgrade_in_place_execution,
    "os-upgrade-postcheck": parse_os_upgrade_postcheck_execution,
    "os-upgrade-preflight": parse_os_upgrade_preflight_execution,
    "scylla-bootstrap": parse_scylla_bootstrap_execution,
    "scylla-cleanup": parse_scylla_cleanup_execution,
    "scylla-cluster-shutdown": parse_scylla_cluster_shutdown_execution,
    "scylla-configure": parse_scylla_configure_execution,
    "scylla-health": parse_scylla_health_execution,
    "scylla-install": parse_scylla_install_execution,
    "scylla-remove-dead": parse_scylla_remove_dead_execution,
    "scylla-remove-live": parse_scylla_remove_live_execution,
    "scylla-repair": parse_scylla_repair_execution,
    "scylla-replace-dead": parse_scylla_replace_dead_execution,
    "service-converge": parse_service_converge_execution,
    "storage-postcheck": parse_storage_postcheck_execution,
    "storage-retire": parse_storage_retire_execution,
}


@dataclass(frozen=True, slots=True)
class ControlledAnsibleExecutionContext:
    """Exact immutable local state supplied to one internal adapter instance."""

    paths: StatePaths
    lock: ClusterLock
    metadata: StoredClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    readiness: ReadinessReport
    binding: StoredOperationPlanBinding


class ControlledAnsibleOperationExecutor:
    """Validate one operation step, invoke the service, and return only a receipt."""

    def __init__(
        self,
        service: AnsibleService,
        context: ControlledAnsibleExecutionContext,
        *,
        evidence_store: OperationEvidenceStore | None = None,
    ) -> None:
        self._service = service
        self._context = context
        self._evidence_store = evidence_store

    def execute(self, step: OperationStepExecution) -> Mapping[str, object]:
        """Execute one exact step without exposing process or evidence content."""

        try:
            _, variables, operation_context = self._validate_current_context(step)
        except (
            AnsibleError,
            StateConflictError,
            StateLockError,
            StatePersistenceError,
            UnsafePathError,
        ):
            return _receipt(step, "failed", 1, _failure_digest("context-refused"))

        try:
            result, rebuilt_digest = self._service.execute_operation_step(
                self._context.lock,
                self._context.metadata.record,
                self._context.inventory,
                step.playbook,
                step_sequence=step.step_sequence,
                limit=step.limit,
                variables=variables,
                readiness=self._context.readiness,
                health_gate_passed=True,
                tags=step.tags,
                check=step.check,
                diff=step.diff,
                verbosity=step.verbosity,
            )
        except KeyboardInterrupt as error:
            raise OperationStepInterrupted(
                "controlled Ansible operation step was interrupted"
            ) from error
        except AnsibleResultError as error:
            raise OperationStepMalformedResult(
                "controlled Ansible operation result was malformed"
            ) from error
        except AnsibleError as error:
            cause = error.__cause__
            if isinstance(cause, ProcessTimeoutError):
                raise OperationStepTimedOut(
                    "controlled Ansible operation step timed out"
                ) from error
            if isinstance(cause, ProcessOutputError):
                raise OperationStepMalformedResult(
                    "controlled Ansible operation output was invalid"
                ) from error
            return _receipt(step, "failed", 1, _failure_digest("service-failed"))
        except (
            StateConflictError,
            StateLockError,
            StatePersistenceError,
            UnsafePathError,
        ):
            return _receipt(step, "failed", 1, _failure_digest("service-refused"))

        if rebuilt_digest != step.command_digest:
            return _receipt(step, "failed", 1, _failure_digest("command-drift"))
        try:
            evidence = _parse_strict_evidence(step, result, variables)
            evidence_object = _evidence_object(evidence)
        except (AnsibleError, TypeError, ValueError) as error:
            raise OperationStepMalformedResult(
                "controlled Ansible operation result was malformed"
            ) from error
        status = _result_status(result.exit_code, evidence_object)
        evidence_digest = digest_bytes(serialize_json(evidence_object))
        if step.operation == "check-jump-hosts":
            if operation_context is None:
                raise OperationStepMalformedResult(
                    "controlled Ansible operation context is missing"
                )
            _, entry = persist_operation_step_evidence(
                self._context.lock,
                self._context.paths,
                self._context.binding,
                operation_context,
                self._context.readiness,
                step,
                evidence,
                store=self._evidence_store,
            )
            evidence_digest = entry.projection_digest
        return _receipt(
            step,
            status,
            result.exit_code,
            evidence_digest,
        )

    def _validate_current_context(
        self, step: OperationStepExecution
    ) -> tuple[
        PlaybookDefinition,
        dict[str, object],
        StoredOperationContext | None,
    ]:
        context = self._context
        paths = context.paths
        expected_paths = StatePaths.derive(paths.state_root, paths.cluster_root.name)
        if expected_paths != paths or self._service.command_builder.paths != paths:
            raise UnsafePathError("controlled Ansible adapter paths are not canonical")
        context.lock.assert_held_for_operation(paths, step.operation)
        binding = OperationPlanBindingStore(paths, step.operation_id).read_locked(
            context.lock,
            expected_cluster_uuid=context.metadata.record.cluster_uuid,
            expected_cluster_name=context.metadata.record.cluster_name,
            expected_operation=step.operation,
        )
        if binding != context.binding:
            raise StateConflictError("Ansible operation binding changed")
        execution = OperationExecutionStore(paths, step.operation_id).read_locked(
            context.lock,
            expected_cluster_uuid=context.metadata.record.cluster_uuid,
            expected_cluster_name=context.metadata.record.cluster_name,
            expected_operation=step.operation,
        )
        attempt = execution.record.attempts[-1]
        if (
            execution.record.binding_digest != binding.digest
            or execution.record.state is not ExecutionAttemptState.STARTED
            or attempt.state is not ExecutionAttemptState.STARTED
            or attempt.step_sequence != step.step_sequence
            or attempt.playbook != step.playbook
            or attempt.classification is not step.classification
            or attempt.limit != step.limit
            or attempt.variables_digest != step.variables_digest
            or attempt.command_digest != step.command_digest
            or attempt.playbook_source_digest != step.playbook_source_digest
            or attempt.result_schema_version != step.result_schema_version
        ):
            raise StateConflictError(
                "controlled Ansible step lacks exact durable started intent"
            )
        current_metadata = ClusterMetadataStore(paths).read(
            expected_cluster_name=context.metadata.record.cluster_name,
            expected_cluster_uuid=context.metadata.record.cluster_uuid,
            expected_provider=context.metadata.record.provider,
        )
        if current_metadata != context.metadata:
            raise StateConflictError("Ansible cluster metadata changed")
        current_observed = ObservedStateStore(paths).read(
            expected_cluster_uuid=context.metadata.record.cluster_uuid,
            expected_cluster_name=context.metadata.record.cluster_name,
            expected_provider=context.metadata.record.provider,
        )
        if current_observed != context.observed:
            raise StateConflictError("Ansible observation changed")
        current_inventory = InventoryStore(paths).read(
            expected_cluster_uuid=context.metadata.record.cluster_uuid,
            expected_cluster_name=context.metadata.record.cluster_name,
            expected_provider=context.metadata.record.provider,
        )
        if current_inventory != context.inventory:
            raise StateConflictError("Ansible inventory changed")
        current_trust = TrustStore(paths).read(
            expected_cluster_uuid=context.metadata.record.cluster_uuid,
            expected_cluster_name=context.metadata.record.cluster_name,
            expected_provider=context.metadata.record.provider,
        )
        if current_trust != context.trust:
            raise StateConflictError("Ansible SSH trust changed")
        TrustStore(paths).validate_runtime(current_trust, current_inventory)
        validate_ansible_config(paths)
        source = load_ansible_source_bundle()
        bound = binding.record
        if (
            source.version != bound.source_version
            or source.digest != bound.source_digest
            or ansible_operation_catalog_digest() != bound.catalog_digest
            or readiness_binding_digest(context.readiness) != bound.readiness_digest
            or current_observed.record.generation != bound.observation_generation
            or current_observed.record.manifest_digest != bound.observation_digest
            or current_inventory.record.generation != bound.inventory_generation
            or current_inventory.digest != bound.inventory_digest
            or current_trust.record.generation != bound.trust_generation
            or current_trust.digest != bound.trust_digest
            or bound.operation_id != step.operation_id
        ):
            raise StateConflictError("controlled Ansible execution context is stale")
        operation_context: StoredOperationContext | None = None
        reconstructed_intent = None
        if step.operation == "check-jump-hosts":
            operation_context = OperationContextStore(
                paths, step.operation_id
            ).read_locked(
                context.lock,
                expected_cluster_uuid=context.metadata.record.cluster_uuid,
                expected_cluster_name=context.metadata.record.cluster_name,
                expected_operation=step.operation,
            )
            reconstructed = reconstruct_operation_context(
                paths,
                operation_context,
                binding,
                current_inventory,
            )
            reconstructed_intent = next(
                (
                    item
                    for item in reconstructed.intents
                    if item.sequence == step.step_sequence
                ),
                None,
            )
            evidence_store = self._evidence_store or OperationEvidenceStore(
                paths, step.operation_id
            )
            if evidence_store.path != operation_evidence_path(paths, step.operation_id):
                raise StateConflictError("operation evidence store scope conflicts")
            validate_state_file(evidence_store.path, allow_missing=True)
            if evidence_store.path.exists():
                stored_evidence = evidence_store.read_locked(
                    context.lock,
                    expected_cluster_uuid=context.metadata.record.cluster_uuid,
                    expected_cluster_name=context.metadata.record.cluster_name,
                    expected_operation=step.operation,
                )
                validate_operation_evidence_checkpoint(
                    stored_evidence,
                    binding=binding,
                    context=operation_context,
                    readiness=context.readiness,
                )
                validate_operation_evidence_intents(
                    stored_evidence, reconstructed.intents
                )
                if len(stored_evidence.record.entries) != step.step_sequence - 1:
                    raise StateConflictError(
                        "operation evidence prefix does not match the next step"
                    )
            elif step.step_sequence != 1:
                raise StateConflictError("operation evidence prefix is missing")
        definition, variables, variables_digest, command_digest = (
            self._service.command_builder.validate_operation_step(
                step.playbook,
                step_sequence=step.step_sequence,
                limit=step.limit,
                variables=step.variables,
                tags=step.tags,
                check=step.check,
                diff=step.diff,
                verbosity=step.verbosity,
            )
        )
        playbook_path = f"playbooks/{definition.filename}"
        source_files = {item.path: item.digest for item in source.files}
        if (
            definition.execution_result_schema_version != step.result_schema_version
            or definition.classification is not step.classification
            or variables_digest != step.variables_digest
            or command_digest != step.command_digest
            or source_files.get(playbook_path) != step.playbook_source_digest
        ):
            raise StateConflictError("controlled Ansible operation step drifted")
        if reconstructed_intent is not None and (
            reconstructed_intent.limit != step.limit
            or dict(reconstructed_intent.variables) != variables
            or reconstructed_intent.tags != step.tags
            or reconstructed_intent.check is not step.check
            or reconstructed_intent.diff is not step.diff
            or reconstructed_intent.verbosity != step.verbosity
        ):
            raise StateConflictError(
                "controlled Ansible operation context step drifted"
            )
        if step.operation == "check-jump-hosts" and reconstructed_intent is None:
            raise StateConflictError(
                "controlled Ansible operation context step is missing"
            )
        return definition, variables, operation_context


def _parse_strict_evidence(
    step: OperationStepExecution,
    result: AnsibleExecutionResult,
    variables: dict[str, object],
) -> object:
    if result.playbook != step.playbook or result.check_mode is not step.check:
        raise AnsibleError("controlled Ansible result identity conflicts")
    if step.playbook == "inventory-preflight":
        if result.inventory_preflight is None:
            raise AnsibleError("Ansible inventory preflight result is missing")
        return result.inventory_preflight
    if step.playbook == "connectivity-check":
        if result.connectivity is None:
            raise AnsibleError("Ansible connectivity result is missing")
        return result.connectivity
    if step.playbook == "evidence-collect":
        if result.evidence is None:
            raise AnsibleError("Ansible collected evidence is missing")
        return result.evidence
    if step.playbook == "base-os":
        if result.base_os is None:
            raise AnsibleError("Ansible base-OS evidence is missing")
        return result.base_os
    if step.playbook == "storage-discover":
        if result.storage_discovery is None:
            raise AnsibleError("Ansible storage discovery evidence is missing")
        return result.storage_discovery
    if step.playbook == "storage-preflight":
        expected = _expected_payload(variables, "deploy_scylla_vms_storage_preflight")
        return parse_storage_preflight_projection(
            result.stdout, expected, result.exit_code
        )
    if step.playbook == "storage-prepare":
        payload = _expected_payload(variables, "deploy_scylla_vms_storage_prepare")
        return parse_storage_prepare_execution(
            result.stdout,
            expected_logical_id=_string_field(payload, "logical_id"),
            expected_backend=_string_field(payload, "backend"),
            expected_layout=_string_field(payload, "layout"),
            expected_device_set_digest=_string_field(
                _mapping_field(payload, "authorization"), "device_set_digest"
            ),
            exit_code=result.exit_code,
        )
    parser = _EXPECTED_PAYLOAD_PARSERS.get(step.playbook)
    if parser is None:
        raise AnsibleError("Ansible playbook has no strict executor result parser")
    payload_name = f"deploy_scylla_vms_{step.playbook.replace('-', '_')}"
    return parser(
        result.stdout,
        expected_payload=_expected_payload(variables, payload_name),
        exit_code=result.exit_code,
    )


def _expected_payload(variables: Mapping[str, object], name: str) -> dict[str, object]:
    value = variables.get(name)
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AnsibleError("Ansible operation result expectation is invalid")
    return value


def _string_field(value: Mapping[str, object], name: str) -> str:
    field = value.get(name)
    if not isinstance(field, str) or not field:
        raise AnsibleError("Ansible operation result expectation is invalid")
    return field


def _mapping_field(value: Mapping[str, object], name: str) -> Mapping[str, object]:
    field = value.get(name)
    if not isinstance(field, Mapping) or not all(isinstance(key, str) for key in field):
        raise AnsibleError("Ansible operation result expectation is invalid")
    return field


def _evidence_object(evidence: object) -> Mapping[str, object]:
    if isinstance(evidence, dict):
        return cast(dict[str, object], evidence)
    if not is_dataclass(evidence) or isinstance(evidence, type):
        raise TypeError("strict Ansible result evidence is not a dataclass")
    return cast(dict[str, object], asdict(evidence))


def _result_status(exit_code: int, evidence: object) -> str:
    if exit_code == 4:
        return "unreachable"
    if exit_code != 0 or _contains_blocker(evidence):
        return "failed"
    return "succeeded"


def _contains_blocker(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key == "blockers" and isinstance(item, (list, tuple)) and item:
                return True
            if (
                key == "status"
                and isinstance(item, str)
                and item in _NON_SUCCESS_STATUSES
            ):
                return True
            if _contains_blocker(item):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_blocker(item) for item in value)
    return False


def _failure_digest(category: str) -> str:
    return digest_bytes(
        serialize_json(
            {
                "category": category,
                "schema_version": _ADAPTER_EVIDENCE_SCHEMA_VERSION,
            }
        )
    )


def _receipt(
    step: OperationStepExecution,
    status: str,
    exit_code: int,
    evidence_digest: str,
) -> dict[str, object]:
    return {
        "command_digest": step.command_digest,
        "evidence_digest": evidence_digest,
        "exit_code": exit_code,
        "playbook": step.playbook,
        "schema_version": step.result_schema_version,
        "status": status,
        "step_sequence": step.step_sequence,
    }
