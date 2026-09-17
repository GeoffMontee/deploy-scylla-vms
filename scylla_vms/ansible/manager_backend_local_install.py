"""Strict package-only install contract for the Manager-local Scylla backend."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum, StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    DeployManagerBackendInstallationPlanStatus,
    DeployManagerBackendInstallationSourceState,
    DeployManagerBackendInstallationStorageState,
    StoredDeployManagerBackendInstallationContext,
    StoredDeployManagerBackendInstallationPlan,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    DeployManagerBackendPreflightInstallationPlanningState,
    StoredDeployManagerBackendPreflightReconciliation,
)
from scylla_vms.ansible.deploy_plan import _digest_object as _planning_digest
from scylla_vms.ansible.manager_backend_preflight import (
    ManagerBackendPreflightStatus,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    ManagerServerEvidence,
    ManagerServerStatus,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_install import (
    SCYLLA_CHANNEL,
    SCYLLA_EDITION,
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_REPOSITORY_URI,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_RESOURCE,
    load_scylla_signing_key,
    validate_scylla_signing_key,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.observed import StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadata

MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-manager-backend-local-install/v1"
)
MANAGER_BACKEND_LOCAL_INSTALL_PLAYBOOK = "manager-backend-local-install"
MANAGER_BACKEND_LOCAL_INSTALL_ROLE = "manager_backend_local_install"
MANAGER_BACKEND_LOCAL_INSTALL_SOURCE_PATHS = (
    "playbooks/manager-backend-local-install.yml",
    (
        "playbooks/roles/manager_backend_local_install/files/"
        "manager-backend-local-install.provenance.yml"
    ),
    "playbooks/roles/manager_backend_local_install/tasks/main.yml",
    "playbooks/roles/scylla_install/files/scylladb-2026-key.provenance.yml",
    "playbooks/roles/scylla_install/files/scylladb-2026.asc",
)
MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS = (
    "cql_performed",
    "manager_agent_token_performed",
    "manager_configuration_performed",
    "registration_performed",
    "schema_or_keyspace_performed",
    "scylla_configuration_rendering_performed",
    "scylla_setup_performed",
    "scyllamgr_setup_performed",
    "service_enabled",
    "service_started",
    "storage_filesystem_mutation_performed",
    "storage_mount_mutation_performed",
    "storage_preparation_performed",
    "tasks_performed",
    "tuning_performed",
)

_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(
    r"DSV_MANAGER_BACKEND_LOCAL_INSTALL_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"
)
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "execution-failed",
        "installed-package-mismatch",
        "service-active",
        "service-unmasked",
    }
)


class ManagerBackendLocalInstallStatus(StrEnum):
    INSTALLED = "installed"
    NO_CHANGE = "no-change"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ManagerBackendLocalInstallEvidence:
    logical_id: str
    role: str
    operating_system: str
    operating_system_version: str
    architecture: str
    status: ManagerBackendLocalInstallStatus
    changed: bool
    requested_release: str
    requested_version: str
    installed_version: str | None
    packages: tuple[tuple[str, str], ...]
    repository_digest: str
    signing_key_fingerprint: str
    signing_key_digest: str
    source_digest: str
    command_policy_digest: str
    service_masked: bool | None
    service_inactive: bool | None
    cql_performed: bool
    manager_agent_token_performed: bool
    manager_configuration_performed: bool
    registration_performed: bool
    schema_or_keyspace_performed: bool
    scylla_configuration_rendering_performed: bool
    scylla_setup_performed: bool
    scyllamgr_setup_performed: bool
    service_enabled: bool
    service_started: bool
    storage_filesystem_mutation_performed: bool
    storage_mount_mutation_performed: bool
    storage_preparation_performed: bool
    tasks_performed: bool
    tuning_performed: bool
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION


def build_manager_backend_local_install_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    manager_server: ManagerServerEvidence,
    preflight_reconciliation: StoredDeployManagerBackendPreflightReconciliation,
    installation_context: StoredDeployManagerBackendInstallationContext,
    installation_plan: StoredDeployManagerBackendInstallationPlan,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
) -> dict[str, object]:
    """Build one exact Manager-role package-only intent."""

    validate_scylla_signing_key(load_scylla_signing_key())
    _validate_current_state(
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        manager_server,
        logical_id=logical_id,
    )
    _validate_platform(
        logical_id=logical_id,
        image_filter=image_filter,
        architecture=architecture,
        base_os=base_os,
    )
    _validate_planning_chain(
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        manager_server,
        preflight_reconciliation,
        installation_context,
        installation_plan,
        logical_id=logical_id,
        architecture=architecture,
    )

    source = load_ansible_source_bundle()
    source_files = {item.path: item.digest for item in source.files}
    if set(MANAGER_BACKEND_LOCAL_INSTALL_SOURCE_PATHS) - set(source_files):
        raise StateConflictError(
            "Manager backend local install source files are incomplete"
        )
    selected_source = {
        path: source_files[path] for path in MANAGER_BACKEND_LOCAL_INSTALL_SOURCE_PATHS
    }
    source_digest = _object_digest(selected_source)
    command_policy_digest = _object_digest(
        {
            "check_mode": "preview",
            "classification": OperationClassification.MUTATING.value,
            "fatal": True,
            "limit": [logical_id],
            "playbook": MANAGER_BACKEND_LOCAL_INSTALL_PLAYBOOK,
            "serial": 1,
            "tags": [
                "manager-backend-local-install",
                "preflight",
                "packages",
                "verify",
            ],
            "variable": "deploy_scylla_vms_manager_backend_local_install",
        }
    )
    context = installation_context.record
    plan = installation_plan.record
    reconciliation = preflight_reconciliation.record
    provenance = {
        "ansible_source_digest": source.digest,
        "base_os_evidence_digest": context.base_os_evidence_digest,
        "catalog_digest": context.catalog_digest,
        "desired_spec_digest": context.desired_spec_digest,
        "installation_context_artifact_digest": installation_context.artifact_digest,
        "installation_context_record_digest": context.record_digest,
        "installation_plan_artifact_digest": installation_plan.artifact_digest,
        "installation_plan_digest": plan.plan_digest,
        "inventory_digest": inventory.digest,
        "manager_server_evidence_digest": context.manager_server_evidence_digest,
        "manager_server_provenance_digest": (context.manager_server_provenance_digest),
        "observation_digest": observed.digest,
        "package_reference_digest": context.package_reference.reference_digest,
        "preflight_reconciliation_artifact_digest": (
            preflight_reconciliation.artifact_digest
        ),
        "preflight_reconciliation_record_digest": reconciliation.record_digest,
        "storage_decision_digest": context.storage_decision.decision_digest,
        "trust_digest": cast(str, readiness.trust_digest),
    }
    return {
        "architecture": architecture,
        "channel": SCYLLA_CHANNEL,
        "cluster_uuid": str(metadata.cluster_uuid),
        "command_policy_digest": command_policy_digest,
        "edition": SCYLLA_EDITION,
        "image_operating_system": "Ubuntu",
        "image_operating_system_version": "24.04",
        "logical_id": logical_id,
        "package_version": SCYLLA_PACKAGE_VERSION,
        "packages": list(SCYLLA_PACKAGES),
        "provenance": provenance,
        "release_line": SCYLLA_RELEASE_LINE,
        "repository": {
            "definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
            "uri": SCYLLA_REPOSITORY_URI,
        },
        "role": "manager",
        "schema_version": MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION,
        "signing_key": {
            "artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
            "fingerprint": SCYLLA_SIGNING_KEY_FINGERPRINT,
            "resource": SCYLLA_SIGNING_KEY_RESOURCE,
        },
        "source_digest": source_digest,
    }


def parse_manager_backend_local_install_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ManagerBackendLocalInstallEvidence:
    """Parse one bounded strict result marker and one exact recap row."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError(
            "Ansible Manager backend local install output exceeds the evidence limit"
        )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MANAGER_BACKEND_LOCAL_INSTALL_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError(
                "Ansible Manager backend local install marker is malformed"
            )
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Manager backend local install marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError(
                "Ansible Manager backend local install evidence is malformed"
            )
        values.append(value)

    _before, separator, after = stdout.partition("PLAY RECAP")
    if not separator:
        raise AnsibleError(
            "Ansible Manager backend local install output omitted PLAY RECAP"
        )
    rows: dict[str, tuple[int, int, int]] = {}
    for line in after.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError(
                "Ansible Manager backend local install recap is malformed"
            )
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError(
            "Ansible Manager backend local install recap membership conflicts"
        )
    changed_count, unreachable, failed_count = rows[logical_id]
    recap_failed = bool(unreachable or failed_count)
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError(
                "Ansible Manager backend local install evidence is incomplete"
            )
        if changed_count:
            raise AnsibleError(
                "Ansible Manager backend local install failure changed state ambiguously"
            )
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError(
            "Ansible Manager backend local install evidence is duplicated"
        )
    evidence = _parse_result(values[0], expected_payload)
    result_failed = evidence.status is ManagerBackendLocalInstallStatus.FAILED
    if recap_failed != result_failed or (exit_code == 0) == result_failed:
        raise AnsibleError(
            "Ansible Manager backend local install exit status conflicts"
        )
    if bool(changed_count) != evidence.changed:
        raise AnsibleError(
            "Ansible Manager backend local install changed status conflicts"
        )
    return evidence


def _validate_platform(
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
    base_os: BaseOsEvidence,
) -> None:
    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError(
            "Manager backend local install requires exact Ubuntu 24.04 evidence"
        )
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError(
            "Manager backend local install requires successful current base-os"
        )


def _validate_current_state(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    manager_server: ManagerServerEvidence,
    *,
    logical_id: str,
) -> None:
    record = inventory.record
    manager_ids = tuple(
        sorted(
            host.logical_id
            for host in record.inventory.hosts
            if host.role.value == "manager"
        )
    )
    if manager_ids != (logical_id,):
        raise StateConflictError(
            "Manager backend local install requires the exact single manager target"
        )
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or observed.record.cluster_uuid != record.cluster_uuid
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.record.manifest_digest
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError(
            "Manager backend local install input provenance conflicts"
        )
    if (
        manager_server.logical_id != logical_id
        or manager_server.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or manager_server.requested_version != MANAGER_PACKAGE_VERSION
        or manager_server.installed_version != MANAGER_PACKAGE_VERSION
        or manager_server.packages
        != tuple((name, MANAGER_PACKAGE_VERSION) for name in MANAGER_PACKAGES)
        or manager_server.service_masked is not True
        or manager_server.service_inactive is not True
        or manager_server.service_started
        or manager_server.backend_configured
        or manager_server.configuration_performed
        or manager_server.registration_performed
        or manager_server.setup_performed
        or manager_server.tasks_performed
        or manager_server.blockers
    ):
        raise StateConflictError(
            "Manager backend local install requires current install-only Manager evidence"
        )
    if _PACKAGE_VERSION.fullmatch(SCYLLA_PACKAGE_VERSION) is None:
        raise AnsibleError(
            "Manager backend local package version must be exact ScyllaDB 2026.2"
        )
    if not base_os.hosts:
        raise StateConflictError("Manager backend local base-os evidence is absent")


def _validate_planning_chain(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    manager_server: ManagerServerEvidence,
    preflight_reconciliation: StoredDeployManagerBackendPreflightReconciliation,
    installation_context: StoredDeployManagerBackendInstallationContext,
    installation_plan: StoredDeployManagerBackendInstallationPlan,
    *,
    logical_id: str,
    architecture: str,
) -> None:
    reconciliation = preflight_reconciliation.record
    context = installation_context.record
    plan = installation_plan.record
    source = load_ansible_source_bundle()
    package = context.package_reference
    storage = context.storage_decision
    if (
        reconciliation.cluster_uuid != metadata.cluster_uuid
        or reconciliation.cluster_name != metadata.cluster_name
        or reconciliation.target_stable_id != logical_id
        or reconciliation.semantic_status
        is not ManagerBackendPreflightStatus.EVIDENCE_READY
        or not reconciliation.host_evidence_ready
        or reconciliation.host_observed_blockers
        or reconciliation.installation_planning_state
        is not DeployManagerBackendPreflightInstallationPlanningState.EVIDENCE_READY
        or reconciliation.journal_status is not JournalStatus.IN_PROGRESS
        or reconciliation.journal_phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "Manager backend local install preflight reconciliation conflicts"
        )
    context_conflicts = (
        (
            "cluster identity",
            context.cluster_uuid != metadata.cluster_uuid
            or context.cluster_name != metadata.cluster_name,
        ),
        ("operation identity", context.operation_id != reconciliation.operation_id),
        ("target identity", context.manager_target_id != logical_id),
        (
            "preflight artifact",
            context.preflight_reconciliation_artifact_digest
            != preflight_reconciliation.artifact_digest
            or context.preflight_reconciliation_record_digest
            != reconciliation.record_digest,
        ),
        (
            "observation",
            context.observation_generation != observed.record.generation
            or context.observation_artifact_digest != observed.digest
            or context.observation_manifest_digest != observed.record.manifest_digest,
        ),
        (
            "inventory",
            context.inventory_generation != inventory.record.generation
            or context.inventory_artifact_digest != inventory.digest
            or context.inventory_digest != inventory.record.inventory_digest,
        ),
        (
            "trust",
            context.trust_generation != readiness.trust_generation
            or context.trust_artifact_digest != readiness.trust_digest,
        ),
        ("catalog", context.catalog_digest != ansible_operation_catalog_digest()),
        ("source", context.ansible_source_digest != source.digest),
        (
            "platform",
            context.operating_system != "Ubuntu"
            or context.operating_system_version != "24.04"
            or context.architecture != architecture,
        ),
        (
            "Manager evidence",
            context.manager_server_provenance_digest
            != _planning_digest(dict(manager_server.provenance)),
        ),
        (
            "service evidence",
            context.manager_service_state != "masked-inactive"
            or context.local_scylla_package_state != "not-installed"
            or context.local_scylla_service_state != "absent",
        ),
        (
            "planning state",
            context.host_planning_state
            is not DeployManagerBackendPreflightInstallationPlanningState.EVIDENCE_READY
            or context.plan_status
            is not DeployManagerBackendInstallationPlanStatus.BLOCKED
            or context.authorization_state != "unavailable"
            or context.execution_state != "not-performed",
        ),
    )
    for label, conflicts in context_conflicts:
        if conflicts:
            raise StateConflictError(
                f"Manager backend local install context {label} conflicts"
            )
    if (
        package.release_line != SCYLLA_RELEASE_LINE
        or package.package_version != SCYLLA_PACKAGE_VERSION
        or package.edition != SCYLLA_EDITION
        or package.channel != SCYLLA_CHANNEL
        or package.package_count != len(SCYLLA_PACKAGES)
        or package.package_set_digest != _planning_digest(list(SCYLLA_PACKAGES))
        or package.package_set_policy
        != "exact-manager-local-backend-package-set-approved"
        or package.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
        or package.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
        or package.authentication_state != "authenticated"
        or package.target_contract_state
        != "manager-backend-local-install-source-available"
    ):
        raise StateConflictError(
            "Manager backend local install package provenance conflicts"
        )
    if (
        storage.state is not DeployManagerBackendInstallationStorageState.IDENTIFIED
        or not storage.dedicated_volume_identified
        or storage.volume_identity_digest is None
        or storage.root_fallback_policy != "forbidden"
        or storage.generic_root_capacity_accepted
    ):
        raise StateConflictError(
            "Manager backend local install requires identified dedicated backend storage"
        )
    if (
        plan.cluster_uuid != metadata.cluster_uuid
        or plan.cluster_name != metadata.cluster_name
        or plan.operation_id != context.operation_id
        or plan.context_artifact_digest != installation_context.artifact_digest
        or plan.context_record_digest != context.record_digest
        or plan.preflight_reconciliation_artifact_digest
        != preflight_reconciliation.artifact_digest
        or plan.preflight_reconciliation_record_digest != reconciliation.record_digest
        or plan.manager_target_id != logical_id
        or plan.storage_state
        is not DeployManagerBackendInstallationStorageState.IDENTIFIED
        or not plan.dedicated_volume_identified
        or plan.status is not DeployManagerBackendInstallationPlanStatus.BLOCKED
        or plan.authorization_state != "package-install-authorization-required"
        or plan.execution_state != "not-performed"
        or not plan.original_mapping_unchanged
        or len(plan.steps) != 9
    ):
        raise StateConflictError(
            "Manager backend local install plan provenance conflicts"
        )
    step = plan.steps[0]
    source_files = {item.path: item.digest for item in source.files}
    package_playbook_source = source_files.get(
        "playbooks/manager-backend-local-install.yml"
    )
    if (
        step.sequence != 1
        or step.boundary != "package-install"
        or step.classification is not OperationClassification.MUTATING
        or step.target_ids != (logical_id,)
        or step.package_reference_digest != package.reference_digest
        or step.storage_decision_digest != storage.decision_digest
        or step.source_state
        is not DeployManagerBackendInstallationSourceState.AVAILABLE
        or step.source_digest != package_playbook_source
        or step.source_contract_state != "manager-backend-local-install-v1"
        or step.authorization_requirement != "ordinary-approval-required"
        or step.status
        is not DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or step.performance_state != "not-performed"
        or step.blockers
        != (
            "deploy-authorization-not-collected",
            "mutating-deploy-execution-unavailable",
            "public-deploy-workflow-unavailable",
        )
    ):
        raise StateConflictError(
            "Manager backend local install package boundary conflicts"
        )


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ManagerBackendLocalInstallEvidence:
    expected_fields = {
        "architecture",
        "blockers",
        "changed",
        "command_policy_digest",
        "installed_version",
        "logical_id",
        "operating_system",
        "operating_system_version",
        "packages",
        "provenance",
        "repository_digest",
        "requested_release",
        "requested_version",
        "role",
        "schema_version",
        "service_inactive",
        "service_masked",
        "signing_key_digest",
        "signing_key_fingerprint",
        "source_digest",
        "status",
        *MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS,
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION
    ):
        raise AnsibleError(
            "Ansible Manager backend local install evidence schema is invalid"
        )
    if (
        value["logical_id"] != expected["logical_id"]
        or value["role"] != "manager"
        or value["operating_system"] != "Ubuntu"
        or value["operating_system_version"] != "24.04"
        or value["architecture"] != expected["architecture"]
        or value["requested_release"] != SCYLLA_RELEASE_LINE
        or value["requested_version"] != SCYLLA_PACKAGE_VERSION
    ):
        raise AnsibleError("Ansible Manager backend local install evidence conflicts")
    try:
        status = ManagerBackendLocalInstallStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError(
            "Ansible Manager backend local install status is invalid"
        ) from error
    changed = _require_bool(value["changed"])
    packages_value = value["packages"]
    if not isinstance(packages_value, dict):
        raise AnsibleError("Ansible Manager backend local install packages are invalid")
    packages = tuple(
        sorted(
            (_text(name), _text(version)) for name, version in packages_value.items()
        )
    )
    blockers = _sorted_strings(value["blockers"])
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible Manager backend local install blocker is unknown")
    provenance = _digest_mapping(value["provenance"])
    if provenance != _digest_mapping(expected["provenance"]):
        raise AnsibleError("Ansible Manager backend local install provenance conflicts")
    repository = cast(dict[str, object], expected["repository"])
    signing_key = cast(dict[str, object], expected["signing_key"])
    repository_digest = _require_digest(value["repository_digest"])
    signing_key_digest = _require_digest(value["signing_key_digest"])
    signing_key_fingerprint = _text(value["signing_key_fingerprint"])
    source_digest = _require_digest(value["source_digest"])
    command_policy_digest = _require_digest(value["command_policy_digest"])
    if (
        repository_digest != repository["definition_digest"]
        or signing_key_digest != signing_key["artifact_digest"]
        or signing_key_fingerprint != signing_key["fingerprint"]
        or source_digest != expected["source_digest"]
        or command_policy_digest != expected["command_policy_digest"]
    ):
        raise AnsibleError(
            "Ansible Manager backend local install source provenance conflicts"
        )
    forbidden = {
        name: _require_bool(value[name])
        for name in MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS
    }
    if any(forbidden.values()):
        raise AnsibleError(
            "Ansible Manager backend local install performed a forbidden action"
        )
    installed_version = _optional_text(value["installed_version"])
    service_masked = _optional_bool(value["service_masked"])
    service_inactive = _optional_bool(value["service_inactive"])
    success = status in {
        ManagerBackendLocalInstallStatus.INSTALLED,
        ManagerBackendLocalInstallStatus.NO_CHANGE,
    }
    expected_packages = tuple(
        (name, SCYLLA_PACKAGE_VERSION) for name in SCYLLA_PACKAGES
    )
    if success and (
        changed != (status is ManagerBackendLocalInstallStatus.INSTALLED)
        or installed_version != SCYLLA_PACKAGE_VERSION
        or packages != expected_packages
        or service_masked is not True
        or service_inactive is not True
        or blockers
    ):
        raise AnsibleError(
            "Ansible Manager backend local install success evidence conflicts"
        )
    if status is ManagerBackendLocalInstallStatus.NOT_PREDICTED and (
        changed
        or installed_version is not None
        or packages
        or service_masked is not None
        or service_inactive is not None
        or blockers
    ):
        raise AnsibleError(
            "Ansible Manager backend local install check evidence conflicts"
        )
    if status is ManagerBackendLocalInstallStatus.FAILED and (
        changed
        or installed_version is not None
        or packages
        or service_masked is not None
        or service_inactive is not None
        or not blockers
    ):
        raise AnsibleError(
            "Ansible Manager backend local install failure evidence conflicts"
        )
    return ManagerBackendLocalInstallEvidence(
        logical_id=_text(value["logical_id"]),
        role="manager",
        operating_system="Ubuntu",
        operating_system_version="24.04",
        architecture=_text(value["architecture"]),
        status=status,
        changed=changed,
        requested_release=SCYLLA_RELEASE_LINE,
        requested_version=SCYLLA_PACKAGE_VERSION,
        installed_version=installed_version,
        packages=packages,
        repository_digest=repository_digest,
        signing_key_fingerprint=signing_key_fingerprint,
        signing_key_digest=signing_key_digest,
        source_digest=source_digest,
        command_policy_digest=command_policy_digest,
        service_masked=service_masked,
        service_inactive=service_inactive,
        cql_performed=forbidden["cql_performed"],
        manager_agent_token_performed=forbidden["manager_agent_token_performed"],
        manager_configuration_performed=forbidden["manager_configuration_performed"],
        registration_performed=forbidden["registration_performed"],
        schema_or_keyspace_performed=forbidden["schema_or_keyspace_performed"],
        scylla_configuration_rendering_performed=forbidden[
            "scylla_configuration_rendering_performed"
        ],
        scylla_setup_performed=forbidden["scylla_setup_performed"],
        scyllamgr_setup_performed=forbidden["scyllamgr_setup_performed"],
        service_enabled=forbidden["service_enabled"],
        service_started=forbidden["service_started"],
        storage_filesystem_mutation_performed=forbidden[
            "storage_filesystem_mutation_performed"
        ],
        storage_mount_mutation_performed=forbidden["storage_mount_mutation_performed"],
        storage_preparation_performed=forbidden["storage_preparation_performed"],
        tasks_performed=forbidden["tasks_performed"],
        tuning_performed=forbidden["tuning_performed"],
        provenance=provenance,
        blockers=blockers,
    )


def _failed_evidence(
    expected: dict[str, object],
) -> ManagerBackendLocalInstallEvidence:
    repository = cast(dict[str, object], expected["repository"])
    signing_key = cast(dict[str, object], expected["signing_key"])
    return ManagerBackendLocalInstallEvidence(
        logical_id=_text(expected["logical_id"]),
        role="manager",
        operating_system="Ubuntu",
        operating_system_version="24.04",
        architecture=_text(expected["architecture"]),
        status=ManagerBackendLocalInstallStatus.FAILED,
        changed=False,
        requested_release=SCYLLA_RELEASE_LINE,
        requested_version=SCYLLA_PACKAGE_VERSION,
        installed_version=None,
        packages=(),
        repository_digest=_require_digest(repository["definition_digest"]),
        signing_key_fingerprint=_text(signing_key["fingerprint"]),
        signing_key_digest=_require_digest(signing_key["artifact_digest"]),
        source_digest=_require_digest(expected["source_digest"]),
        command_policy_digest=_require_digest(expected["command_policy_digest"]),
        service_masked=None,
        service_inactive=None,
        cql_performed=False,
        manager_agent_token_performed=False,
        manager_configuration_performed=False,
        registration_performed=False,
        schema_or_keyspace_performed=False,
        scylla_configuration_rendering_performed=False,
        scylla_setup_performed=False,
        scyllamgr_setup_performed=False,
        service_enabled=False,
        service_started=False,
        storage_filesystem_mutation_performed=False,
        storage_mount_mutation_performed=False,
        storage_preparation_performed=False,
        tasks_performed=False,
        tuning_performed=False,
        provenance=_digest_mapping(expected["provenance"]),
        blockers=("execution-failed",),
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Manager backend local install value is invalid")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _optional_bool(value: object) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise AnsibleError("Ansible Manager backend local install boolean is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible Manager backend local install boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Manager backend local install digest is invalid")
    return text


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible Manager backend local install blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            "Ansible Manager backend local install blockers are not uniquely sorted"
        )
    return items


def _digest_mapping(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or len(value) > 32:
        raise AnsibleError(
            "Ansible Manager backend local install provenance is invalid"
        )
    result = tuple(
        sorted((_text(name), _require_digest(item)) for name, item in value.items())
    )
    if len(result) != len(value):
        raise AnsibleError(
            "Ansible Manager backend local install provenance is invalid"
        )
    return result


def _object_digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _canonical(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _canonical(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    return value
