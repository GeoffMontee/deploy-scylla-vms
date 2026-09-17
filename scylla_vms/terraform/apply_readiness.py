"""Operation-bound local Ansible inventory validation after deploy SSH trust."""

from __future__ import annotations

import os
import stat
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import (
    READINESS_SCHEMA_VERSION,
    EvidenceStatus,
    InventoryListMachineEvidence,
    ReadinessReport,
    build_readiness_report,
)
from scylla_vms.ansible.service import AnsibleService, ProcessRunnerProtocol
from scylla_vms.ansible.source import (
    ANSIBLE_SOURCE_VERSION,
    AnsibleSourceBundle,
    load_ansible_source_bundle,
    stage_ansible_config,
    validate_ansible_config,
)
from scylla_vms.ansible.toolchain import (
    AnsibleToolchain,
    parse_ansible_core_version,
)
from scylla_vms.ansible.trust import (
    TRUST_SCHEMA_VERSION,
    StoredTrustRecord,
    TrustStore,
)
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    ToolExecutionError,
    ToolPrerequisiteError,
    UnsafePathError,
)
from scylla_vms.inventory import INVENTORY_SCHEMA_VERSION
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    JournalStatus,
    OperationPhase,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import OBSERVED_STATE_SCHEMA_VERSION
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
    refuse_unexpected_terraform_state,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_inventory import (
    TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION,
)
from scylla_vms.terraform.apply_trust import (
    TERRAFORM_APPLY_TRUST_SCHEMA_VERSION,
    StoredTerraformApplyTrust,
    TerraformApplyTrustStore,
    _load_trust_context,
    _TrustContext,
    _validate_trust_semantics,
)
from scylla_vms.terraform.apply_trust import (
    _create_companion as _create_expected_trust_companion,
)
from scylla_vms.terraform.apply_verification import (
    TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION,
)
from scylla_vms.terraform.outputs import MAXIMUM_HOSTS
from scylla_vms.terraform.source import TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION

TERRAFORM_APPLY_READINESS_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-readiness/v1"
)
TERRAFORM_APPLY_READINESS_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-readiness-report/v1"
)
ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-inventory-machine-evidence/v1"
)
TERRAFORM_APPLY_READINESS_FILENAME_SUFFIX = ".terraform-apply-readiness.json"

_OPERATION = "deploy"
_NOT_PERFORMED = "not-performed"
_NOT_STARTED = "not-started"


class TerraformApplyReadinessStageState(StrEnum):
    CREATED = "created"
    VALIDATED = "validated"
    REUSED = "reused"


class TerraformApplyReadinessCompanionState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class TerraformApplyReadiness:
    """Immutable redacted binding for local machine inventory readiness."""

    generation: int
    validated_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    verification_generation: int
    verification_artifact_digest: str
    verification_record_digest: str
    apply_inventory_generation: int
    apply_inventory_artifact_digest: str
    apply_inventory_record_digest: str
    apply_trust_generation: int
    apply_trust_artifact_digest: str
    apply_trust_record_digest: str
    metadata_generation: int
    metadata_digest: str
    desired_spec_digest: str
    source_generation: int
    source_artifact_digest: str
    source_version: str
    source_bundle_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    known_hosts_digest: str
    ssh_config_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    config_digest: str
    playbook_version: str
    inventory_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    machine_evidence_digest: str
    readiness_digest: str
    readiness_status: EvidenceStatus
    host_count: int
    group_count: int
    direct_host_count: int
    proxied_host_count: int
    jump_host_count: int
    group_digest: str
    topology_digest: str
    route_digest: str
    remote_connectivity_status: str
    remote_health_status: str
    remote_playbook_status: str
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    verification_schema_version: str = TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
    apply_inventory_schema_version: str = TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
    apply_trust_schema_version: str = TERRAFORM_APPLY_TRUST_SCHEMA_VERSION
    source_schema_version: str = TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
    observation_schema_version: str = OBSERVED_STATE_SCHEMA_VERSION
    inventory_schema_version: str = INVENTORY_SCHEMA_VERSION
    trust_schema_version: str = TRUST_SCHEMA_VERSION
    machine_evidence_schema_version: str = (
        ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = READINESS_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.verification_schema_version
            != TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
            or self.apply_inventory_schema_version
            != TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
            or self.apply_trust_schema_version != TERRAFORM_APPLY_TRUST_SCHEMA_VERSION
            or self.source_schema_version != TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
            or self.observation_schema_version != OBSERVED_STATE_SCHEMA_VERSION
            or self.inventory_schema_version != INVENTORY_SCHEMA_VERSION
            or self.trust_schema_version != TRUST_SCHEMA_VERSION
            or self.machine_evidence_schema_version
            != ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != READINESS_SCHEMA_VERSION
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.generation != 1
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or self.operation != _OPERATION
            or self.readiness_status is not EvidenceStatus.FRESH
        ):
            raise StatePersistenceError("unsupported Terraform apply readiness record")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.validated_at)
        for count_value in (
            self.journal_generation,
            self.verification_generation,
            self.apply_inventory_generation,
            self.apply_trust_generation,
            self.metadata_generation,
            self.source_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.host_count,
            self.group_count,
        ):
            if (
                isinstance(count_value, bool)
                or not isinstance(count_value, int)
                or count_value < 1
            ):
                raise StatePersistenceError(
                    "Terraform apply readiness generation or count is invalid"
                )
        for count_value in (
            self.direct_host_count,
            self.proxied_host_count,
            self.jump_host_count,
        ):
            if (
                isinstance(count_value, bool)
                or not isinstance(count_value, int)
                or count_value < 0
            ):
                raise StatePersistenceError(
                    "Terraform apply readiness route count is invalid"
                )
        if (
            self.host_count > MAXIMUM_HOSTS
            or self.group_count > 4 * self.host_count
            or self.direct_host_count + self.proxied_host_count != self.host_count
            or self.jump_host_count > self.direct_host_count
            or not self.source_version
            or self.remote_connectivity_status != _NOT_PERFORMED
            or self.remote_health_status != _NOT_PERFORMED
            or self.remote_playbook_status != _NOT_PERFORMED
        ):
            raise StatePersistenceError("Terraform apply readiness summary is invalid")
        _validate_version_string(self.playbook_version, "ansible-playbook")
        _validate_version_string(self.inventory_version, "ansible-inventory")
        if self.playbook_version != self.inventory_version:
            raise StatePersistenceError(
                "Terraform apply readiness Ansible versions conflict"
            )
        for label, digest_value in (
            ("operation request", self.request_digest),
            ("journal", self.journal_digest),
            ("verification artifact", self.verification_artifact_digest),
            ("verification record", self.verification_record_digest),
            ("apply inventory artifact", self.apply_inventory_artifact_digest),
            ("apply inventory record", self.apply_inventory_record_digest),
            ("apply trust artifact", self.apply_trust_artifact_digest),
            ("apply trust record", self.apply_trust_record_digest),
            ("metadata", self.metadata_digest),
            ("desired specification", self.desired_spec_digest),
            ("source artifact", self.source_artifact_digest),
            ("source bundle", self.source_bundle_digest),
            ("observation artifact", self.observation_artifact_digest),
            ("observation manifest", self.observation_manifest_digest),
            ("inventory artifact", self.inventory_artifact_digest),
            ("inventory", self.inventory_digest),
            ("trust artifact", self.trust_artifact_digest),
            ("trust entries", self.trust_entries_digest),
            ("known hosts", self.known_hosts_digest),
            ("SSH config", self.ssh_config_digest),
            ("Ansible source", self.ansible_source_digest),
            ("Ansible config", self.config_digest),
            ("executable identity", self.executable_identity_digest),
            ("toolchain evidence", self.toolchain_evidence_digest),
            ("machine inventory evidence", self.machine_evidence_digest),
            ("readiness", self.readiness_digest),
            ("group", self.group_digest),
            ("topology", self.topology_digest),
            ("route", self.route_digest),
            ("record", self.record_digest),
        ):
            validate_digest(
                digest_value,
                f"Terraform apply readiness {label} digest",
            )
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "Terraform apply readiness record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            name: (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, StrEnum)
                else value
            )
            for name, value in (
                (field_name, getattr(self, field_name))
                for field_name in self.__dataclass_fields__
            )
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformApplyReadiness:
        require_exact_keys(
            value,
            set(TerraformApplyReadiness.__dataclass_fields__),
            "Terraform apply readiness record",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "verification_generation",
            "apply_inventory_generation",
            "apply_trust_generation",
            "metadata_generation",
            "source_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "host_count",
            "group_count",
            "direct_host_count",
            "proxied_host_count",
            "jump_host_count",
        }
        parsed: dict[str, object] = {}
        for name in TerraformApplyReadiness.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
            elif name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name == "readiness_status":
                try:
                    parsed[name] = EvidenceStatus(require_string(value, name))
                except ValueError as error:
                    raise StatePersistenceError(
                        "Terraform apply readiness status is invalid"
                    ) from error
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredTerraformApplyReadiness:
    record: TerraformApplyReadiness
    artifact_digest: str


class TerraformApplyReadinessStore:
    """Owner-only immutable local-readiness operation companion."""

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
            raise StatePersistenceError(
                "Terraform apply readiness operation ID must be a UUID"
            )
        self._paths = paths
        self._operation_id = operation_id
        self._path = terraform_apply_readiness_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path,
            replace=replace,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredTerraformApplyReadiness:
        value, artifact_digest = self._file.read()
        record = TerraformApplyReadiness.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != _OPERATION
        ):
            raise StatePersistenceError("Terraform apply readiness identity conflicts")
        return StoredTerraformApplyReadiness(record, artifact_digest)

    def write_locked(
        self,
        record: TerraformApplyReadiness,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredTerraformApplyReadiness:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Terraform apply readiness operation ID conflicts"
            )
        if self._path.exists():
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if (
                expected_generation != current.record.generation
                or expected_digest != current.artifact_digest
            ):
                raise StatePersistenceError(
                    "Terraform apply readiness changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Terraform apply readiness is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Terraform apply readiness requires generation one"
            )
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredTerraformApplyReadiness(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class TerraformApplyReadinessReport:
    """Strict redacted result of local machine inventory validation."""

    operation_id: uuid.UUID
    config_state: TerraformApplyReadinessStageState
    toolchain_state: TerraformApplyReadinessStageState
    machine_validation_state: TerraformApplyReadinessStageState
    companion_state: TerraformApplyReadinessCompanionState
    config_digest: str
    toolchain_evidence_digest: str
    machine_evidence_digest: str
    readiness_digest: str
    readiness_status: EvidenceStatus
    playbook_version: str
    inventory_version: str
    companion_artifact_digest: str
    companion_record_digest: str
    observation_generation: int
    observation_manifest_digest: str
    inventory_generation: int
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    host_count: int
    group_count: int
    direct_host_count: int
    proxied_host_count: int
    jump_host_count: int
    topology_digest: str
    route_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    remote_connectivity_status: str
    remote_health_status: str
    remote_playbook_status: str
    ansible_deployment_state: str
    finalization_state: str
    runner_invoked: bool
    safe_reentry_allowed: bool
    automatic_retry_allowed: bool
    manual_recovery_required: bool
    companion_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    readiness_schema_version: str = READINESS_SCHEMA_VERSION
    machine_evidence_schema_version: str = (
        ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_READINESS_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_READINESS_REPORT_SCHEMA_VERSION
            or self.companion_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.readiness_schema_version != READINESS_SCHEMA_VERSION
            or self.machine_evidence_schema_version
            != ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or self.readiness_status is not EvidenceStatus.FRESH
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.remote_connectivity_status != _NOT_PERFORMED
            or self.remote_health_status != _NOT_PERFORMED
            or self.remote_playbook_status != _NOT_PERFORMED
            or self.ansible_deployment_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or not self.safe_reentry_allowed
            or not self.automatic_retry_allowed
            or self.manual_recovery_required
        ):
            raise StatePersistenceError("Terraform apply readiness report is invalid")
        for count_value in (
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.host_count,
            self.group_count,
            self.journal_generation,
        ):
            if (
                isinstance(count_value, bool)
                or not isinstance(count_value, int)
                or count_value < 1
            ):
                raise StatePersistenceError(
                    "Terraform apply readiness report count is invalid"
                )
        if (
            self.host_count > MAXIMUM_HOSTS
            or self.direct_host_count < 0
            or self.proxied_host_count < 0
            or self.jump_host_count < 0
            or self.direct_host_count + self.proxied_host_count != self.host_count
            or self.jump_host_count > self.direct_host_count
        ):
            raise StatePersistenceError(
                "Terraform apply readiness report summary is invalid"
            )
        for digest_value in (
            self.config_digest,
            self.toolchain_evidence_digest,
            self.machine_evidence_digest,
            self.readiness_digest,
            self.companion_artifact_digest,
            self.companion_record_digest,
            self.observation_manifest_digest,
            self.inventory_digest,
            self.trust_artifact_digest,
            self.topology_digest,
            self.route_digest,
            self.journal_digest,
        ):
            validate_digest(
                digest_value,
                "Terraform apply readiness report digest",
            )

    def to_object(self) -> dict[str, object]:
        return {
            "companion": {
                "artifact_digest": self.companion_artifact_digest,
                "record_digest": self.companion_record_digest,
                "schema_version": self.companion_schema_version,
                "state": self.companion_state.value,
            },
            "controller": {
                "config_digest": self.config_digest,
                "config_state": self.config_state.value,
                "inventory_version": self.inventory_version,
                "playbook_version": self.playbook_version,
                "toolchain_evidence_digest": self.toolchain_evidence_digest,
                "toolchain_state": self.toolchain_state.value,
            },
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "schema_version": self.journal_schema_version,
                "status": self.journal_status.value,
            },
            "machine_inventory": {
                "evidence_digest": self.machine_evidence_digest,
                "schema_version": self.machine_evidence_schema_version,
                "state": self.machine_validation_state.value,
            },
            "operation": {"id": str(self.operation_id), "kind": _OPERATION},
            "pending": {
                "ansible_deployment": self.ansible_deployment_state,
                "finalization": self.finalization_state,
            },
            "readiness": {
                "digest": self.readiness_digest,
                "schema_version": self.readiness_schema_version,
                "status": self.readiness_status.value,
            },
            "recovery": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "manual_recovery_required": self.manual_recovery_required,
                "runner_invoked": self.runner_invoked,
                "safe_reentry_allowed": self.safe_reentry_allowed,
            },
            "remote_checks": {
                "connectivity": self.remote_connectivity_status,
                "health": self.remote_health_status,
                "playbooks": self.remote_playbook_status,
            },
            "schema_version": self.schema_version,
            "summary": {
                "direct_host_count": self.direct_host_count,
                "group_count": self.group_count,
                "host_count": self.host_count,
                "jump_host_count": self.jump_host_count,
                "proxied_host_count": self.proxied_host_count,
                "route_digest": self.route_digest,
                "topology_digest": self.topology_digest,
            },
            "provenance": {
                "inventory": {
                    "digest": self.inventory_digest,
                    "generation": self.inventory_generation,
                },
                "observation": {
                    "generation": self.observation_generation,
                    "manifest_digest": self.observation_manifest_digest,
                },
                "trust": {
                    "artifact_digest": self.trust_artifact_digest,
                    "generation": self.trust_generation,
                },
            },
        }


@dataclass(frozen=True, slots=True)
class _ReadinessContext:
    deploy: _TrustContext
    trust: StoredTrustRecord
    apply_trust: StoredTerraformApplyTrust
    ansible_source: AnsibleSourceBundle


def validate_deploy_ansible_readiness(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> TerraformApplyReadinessReport:
    """Validate local machine inventory without running a remote playbook."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply readiness operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    _assert_operation_lock(lock, paths)
    if not callable(getattr(runner, "run", None)):
        raise StatePersistenceError("Terraform apply readiness runner is invalid")
    if not isinstance(executables, ControlledAnsibleExecutables):
        raise ToolPrerequisiteError("Terraform apply readiness executables are invalid")
    _validate_toolchain_dependency(toolchain)
    _validate_initialized_layout(paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_readiness_context(paths, operation_id)
    executable_identity = _executable_identity_digest(executables)

    store = TerraformApplyReadinessStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    companion_exists = store.path.exists()
    config_existed = paths.ansible_config.exists()
    if config_existed:
        config_digest = validate_ansible_config(paths)
        config_state = TerraformApplyReadinessStageState.REUSED
    else:
        config_digest = stage_ansible_config(paths, lock=lock)
        config_state = TerraformApplyReadinessStageState.CREATED

    if companion_exists and config_existed:
        stored = store.read(
            expected_cluster_uuid=context.deploy.metadata.record.cluster_uuid,
            expected_cluster_name=context.deploy.metadata.record.cluster_name,
        )
        readiness = _reconstructed_readiness(context)
        expected = _create_companion(
            context,
            config_digest=config_digest,
            executable_identity_digest=executable_identity,
            toolchain=toolchain,
            machine_evidence_digest=stored.record.machine_evidence_digest,
            readiness=readiness,
            validated_at=stored.record.validated_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "Terraform apply readiness companion binding changed"
            )
        return _report(
            stored,
            context,
            config_state=config_state,
            toolchain_state=TerraformApplyReadinessStageState.REUSED,
            machine_state=TerraformApplyReadinessStageState.REUSED,
            companion_state=TerraformApplyReadinessCompanionState.REUSED,
            runner_invoked=False,
        )

    builder = AnsibleCommandBuilder(
        executables.playbook,
        executables.inventory,
        paths,
    )
    service = AnsibleService(builder, runner)
    try:
        actual_toolchain = service.version(lock)
    except (AnsibleError, ToolExecutionError, ToolPrerequisiteError) as error:
        raise ToolPrerequisiteError(
            "controlled Ansible toolchain validation failed"
        ) from error
    if actual_toolchain != toolchain:
        raise ToolPrerequisiteError(
            "controlled Ansible toolchain differs from the validated dependency"
        )
    try:
        readiness, machine = service.validate_inventory_list(
            lock,
            context.deploy.observation,
            context.deploy.inventory,
            context.trust,
        )
    except (AnsibleError, StateConflictError, ToolExecutionError) as error:
        raise AnsibleError(
            "controlled local Ansible inventory validation failed"
        ) from error
    readiness.require_ready(OperationClassification.READ_ONLY)
    machine_digest = _machine_evidence_digest(
        context,
        config_digest=config_digest,
        executable_identity_digest=executable_identity,
        toolchain=actual_toolchain,
        machine=machine,
    )
    _reload_exact_context(
        paths,
        operation_id,
        context,
        config_digest=config_digest,
        executables=executables,
        executable_identity_digest=executable_identity,
    )
    validated_at = (
        store.read(
            expected_cluster_uuid=context.deploy.metadata.record.cluster_uuid,
            expected_cluster_name=context.deploy.metadata.record.cluster_name,
        ).record.validated_at
        if companion_exists
        else format_timestamp(datetime.now(UTC))
    )
    expected = _create_companion(
        context,
        config_digest=config_digest,
        executable_identity_digest=executable_identity,
        toolchain=actual_toolchain,
        machine_evidence_digest=machine_digest,
        readiness=readiness,
        validated_at=validated_at,
    )
    if companion_exists:
        stored = store.read(
            expected_cluster_uuid=context.deploy.metadata.record.cluster_uuid,
            expected_cluster_name=context.deploy.metadata.record.cluster_name,
        )
        if stored.record != expected:
            raise StateConflictError(
                "Terraform apply readiness companion conflicts with local validation"
            )
        companion_state = TerraformApplyReadinessCompanionState.REUSED
    else:
        stored = store.write_locked(
            expected,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        companion_state = TerraformApplyReadinessCompanionState.CREATED
    _reload_exact_context(
        paths,
        operation_id,
        context,
        config_digest=config_digest,
        executables=executables,
        executable_identity_digest=executable_identity,
    )
    return _report(
        stored,
        context,
        config_state=config_state,
        toolchain_state=TerraformApplyReadinessStageState.VALIDATED,
        machine_state=TerraformApplyReadinessStageState.VALIDATED,
        companion_state=companion_state,
        runner_invoked=True,
    )


def terraform_apply_readiness_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    """Return the sole canonical deploy-readiness companion path."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply readiness operation ID must be a UUID"
        )
    path = (
        paths.terraform_plans
        / f"{operation_id}{TERRAFORM_APPLY_READINESS_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform apply readiness path is not canonical")
    return path


def _load_readiness_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> _ReadinessContext:
    deploy = _load_trust_context(paths, operation_id)
    validate_state_file(paths.ansible_trust, allow_missing=True)
    if not paths.ansible_trust.exists():
        raise StateConflictError(
            "Terraform apply readiness requires complete current SSH trust"
        )
    trust = TrustStore(paths).read(
        expected_cluster_uuid=deploy.metadata.record.cluster_uuid,
        expected_cluster_name=deploy.metadata.record.cluster_name,
        expected_provider=deploy.metadata.record.provider,
    )
    _validate_trust_semantics(trust, deploy)
    hosts = {host.logical_id for host in deploy.inventory.record.inventory.hosts}
    trusted = {entry.logical_id for entry in trust.record.entries}
    if trusted != hosts or not trust.record.is_fresh_for(
        deploy.observation.record,
        deploy.inventory.record,
    ):
        raise StateConflictError(
            "Terraform apply readiness requires complete current SSH trust"
        )
    TrustStore(paths).validate_runtime(trust, deploy.inventory)

    trust_path = paths.terraform_plans / f"{operation_id}.terraform-apply-trust.json"
    validate_state_file(trust_path, allow_missing=True)
    if not trust_path.exists():
        raise StateConflictError(
            "Terraform apply readiness requires the complete deploy trust companion"
        )
    apply_trust = TerraformApplyTrustStore(paths, operation_id).read(
        expected_cluster_uuid=deploy.metadata.record.cluster_uuid,
        expected_cluster_name=deploy.metadata.record.cluster_name,
    )
    expected_trust = _create_expected_trust_companion(
        paths,
        deploy,
        trust,
        completed_at=apply_trust.record.completed_at,
        proof_digest=apply_trust.record.confirmation_proof_digest,
    )
    if apply_trust.record != expected_trust:
        raise StateConflictError(
            "Terraform apply readiness trust companion is stale or conflicting"
        )
    return _ReadinessContext(
        deploy,
        trust,
        apply_trust,
        load_ansible_source_bundle(),
    )


def _reconstructed_readiness(context: _ReadinessContext) -> ReadinessReport:
    marker = digest_bytes(b"operation-bound-machine-inventory-evidence-present")
    readiness = build_readiness_report(
        context.deploy.observation,
        context.deploy.inventory,
        context.trust,
        machine_evidence=InventoryListMachineEvidence(
            marker,
            len(context.deploy.inventory.record.inventory.hosts),
            len(context.deploy.inventory.record.inventory.groups),
        ),
    )
    readiness.require_ready(OperationClassification.READ_ONLY)
    return readiness


def _create_companion(
    context: _ReadinessContext,
    *,
    config_digest: str,
    executable_identity_digest: str,
    toolchain: AnsibleToolchain,
    machine_evidence_digest: str,
    readiness: ReadinessReport,
    validated_at: str,
) -> TerraformApplyReadiness:
    deploy = context.deploy
    inventory_companion = deploy.apply_inventory.record
    trust_companion = context.apply_trust.record
    route = readiness.route
    version = str(toolchain.core)
    values: dict[str, object] = {
        "ansible_source_digest": context.ansible_source.digest,
        "ansible_source_version": context.ansible_source.version,
        "apply_inventory_artifact_digest": deploy.apply_inventory.artifact_digest,
        "apply_inventory_generation": inventory_companion.generation,
        "apply_inventory_record_digest": inventory_companion.record_digest,
        "apply_inventory_schema_version": inventory_companion.schema_version,
        "apply_trust_artifact_digest": context.apply_trust.artifact_digest,
        "apply_trust_generation": trust_companion.generation,
        "apply_trust_record_digest": trust_companion.record_digest,
        "apply_trust_schema_version": trust_companion.schema_version,
        "cluster_name": deploy.metadata.record.cluster_name,
        "cluster_uuid": str(deploy.metadata.record.cluster_uuid),
        "config_digest": config_digest,
        "desired_spec_digest": deploy.metadata.record.desired_spec.digest(),
        "direct_host_count": route.direct_hosts,
        "executable_identity_digest": executable_identity_digest,
        "generation": 1,
        "group_count": inventory_companion.group_count,
        "group_digest": inventory_companion.group_digest,
        "host_count": inventory_companion.host_count,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_schema_version": deploy.inventory.record.schema_version,
        "inventory_version": version,
        "journal_digest": deploy.journal.digest,
        "journal_generation": deploy.journal.record.generation,
        "journal_schema_version": deploy.journal.record.schema_version,
        "jump_host_count": route.jump_hosts,
        "known_hosts_digest": _runtime_file_digest(
            deploy.apply_inventory,
            context.apply_trust,
            "known-hosts",
            trust_companion.known_hosts_digest,
        ),
        "machine_evidence_digest": machine_evidence_digest,
        "machine_evidence_schema_version": (
            ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION
        ),
        "metadata_digest": deploy.metadata.digest,
        "metadata_generation": deploy.metadata.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_generation": deploy.observation.record.generation,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "observation_schema_version": deploy.observation.record.schema_version,
        "operation": _OPERATION,
        "operation_id": str(deploy.journal.record.operation_id),
        "playbook_version": version,
        "proxied_host_count": route.proxied_hosts,
        "readiness_digest": readiness_binding_digest(readiness),
        "readiness_schema_version": readiness.schema_version,
        "readiness_status": readiness.status.value,
        "record_digest": "sha256:" + "0" * 64,
        "remote_connectivity_status": _NOT_PERFORMED,
        "remote_health_status": _NOT_PERFORMED,
        "remote_playbook_status": _NOT_PERFORMED,
        "request_digest": deploy.journal.record.request_digest,
        "route_digest": inventory_companion.route_digest,
        "schema_version": TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
        "source_artifact_digest": deploy.source.digest,
        "source_bundle_digest": deploy.source.record.bundle_digest,
        "source_generation": deploy.source.record.generation,
        "source_schema_version": deploy.source.record.schema_version,
        "source_version": deploy.source.record.source_version,
        "ssh_config_digest": _runtime_file_digest(
            deploy.apply_inventory,
            context.apply_trust,
            "ssh-config",
            trust_companion.ssh_config_digest,
        ),
        "toolchain_evidence_digest": _toolchain_evidence_digest(
            toolchain,
            executable_identity_digest,
        ),
        "topology_digest": inventory_companion.topology_digest,
        "trust_artifact_digest": context.trust.digest,
        "trust_entries_digest": context.trust.record.entries_digest,
        "trust_generation": context.trust.record.generation,
        "trust_schema_version": context.trust.record.schema_version,
        "validated_at": validated_at,
        "verification_artifact_digest": deploy.verification.artifact_digest,
        "verification_generation": deploy.verification.record.generation,
        "verification_record_digest": deploy.verification.record.record_digest,
        "verification_schema_version": deploy.verification.record.schema_version,
    }
    values["record_digest"] = _record_digest_object(values)
    return TerraformApplyReadiness.from_object(values)


def _runtime_file_digest(
    apply_inventory: object,
    apply_trust: object,
    label: str,
    expected_digest: str,
) -> str:
    # The runtime files were already read and compared by TrustStore. Keep this
    # helper deliberately value-only so neither a path nor file content can enter
    # the companion creation interface.
    del apply_inventory, apply_trust, label
    validate_digest(expected_digest, "Terraform apply readiness derivative digest")
    return expected_digest


def _machine_evidence_digest(
    context: _ReadinessContext,
    *,
    config_digest: str,
    executable_identity_digest: str,
    toolchain: AnsibleToolchain,
    machine: InventoryListMachineEvidence,
) -> str:
    if machine.host_count != len(
        context.deploy.inventory.record.inventory.hosts
    ) or machine.group_count != len(context.deploy.inventory.record.inventory.groups):
        raise StateConflictError("Ansible machine inventory evidence count conflicts")
    return digest_bytes(
        serialize_json(
            {
                "config_digest": config_digest,
                "executable_identity_digest": executable_identity_digest,
                "group_count": machine.group_count,
                "host_count": machine.host_count,
                "inventory_artifact_digest": context.deploy.inventory.digest,
                "inventory_digest": context.deploy.inventory.record.inventory_digest,
                "inventory_generation": context.deploy.inventory.record.generation,
                "list_digest": machine.list_digest,
                "schema_version": (ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION),
                "toolchain_evidence_digest": _toolchain_evidence_digest(
                    toolchain,
                    executable_identity_digest,
                ),
            }
        )
    )


def _toolchain_evidence_digest(
    toolchain: AnsibleToolchain,
    executable_identity_digest: str,
) -> str:
    return digest_bytes(
        serialize_json(
            {
                "executable_identity_digest": executable_identity_digest,
                "inventory_version": str(toolchain.core),
                "playbook_version": str(toolchain.core),
                "schema_version": "deploy-scylla-vms.ansible-toolchain-evidence/v1",
            }
        )
    )


def _executable_identity_digest(executables: ControlledAnsibleExecutables) -> str:
    values: list[dict[str, object]] = []
    for name, path in (
        ("ansible-inventory", executables.inventory),
        ("ansible-playbook", executables.playbook),
    ):
        try:
            info = path.lstat()
        except OSError as error:
            raise ToolPrerequisiteError(
                "controlled Ansible executable identity is unavailable"
            ) from error
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not os.access(path, os.X_OK)
            or path.name != name
        ):
            raise ToolPrerequisiteError(
                "controlled Ansible executable identity is invalid"
            )
        values.append(
            {
                "change_time_ns": info.st_ctime_ns,
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode),
                "modification_time_ns": info.st_mtime_ns,
                "name": name,
                "size": info.st_size,
            }
        )
    return digest_bytes(
        serialize_json(
            {
                "executables": values,
                "schema_version": "deploy-scylla-vms.executable-identity/v1",
            }
        )
    )


def _validate_toolchain_dependency(toolchain: AnsibleToolchain) -> None:
    if not isinstance(toolchain, AnsibleToolchain) or toolchain != AnsibleToolchain(
        toolchain.core
    ):
        raise ToolPrerequisiteError(
            "Terraform apply readiness toolchain dependency is invalid"
        )
    _validate_version_string(str(toolchain.core), "ansible-playbook")
    _validate_version_string(str(toolchain.core), "ansible-inventory")


def _validate_version_string(value: str, executable: str) -> None:
    parsed = parse_ansible_core_version(
        f"{executable} [core {value}]\n",
        expected_executable=executable,
    )
    if str(parsed) != value:
        raise StatePersistenceError("Ansible toolchain version is invalid")


def _reload_exact_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    expected: _ReadinessContext,
    *,
    config_digest: str,
    executables: ControlledAnsibleExecutables,
    executable_identity_digest: str,
) -> None:
    current = _load_readiness_context(paths, operation_id)
    if current != expected:
        raise StateConflictError(
            "Terraform apply readiness inputs changed during local validation"
        )
    if validate_ansible_config(paths) != config_digest:
        raise StateConflictError(
            "Terraform apply readiness configuration changed during validation"
        )
    if _executable_identity_digest(executables) != executable_identity_digest:
        raise ToolPrerequisiteError(
            "controlled Ansible executable identity changed during validation"
        )


def _report(
    stored: StoredTerraformApplyReadiness,
    context: _ReadinessContext,
    *,
    config_state: TerraformApplyReadinessStageState,
    toolchain_state: TerraformApplyReadinessStageState,
    machine_state: TerraformApplyReadinessStageState,
    companion_state: TerraformApplyReadinessCompanionState,
    runner_invoked: bool,
) -> TerraformApplyReadinessReport:
    record = stored.record
    return TerraformApplyReadinessReport(
        operation_id=record.operation_id,
        config_state=config_state,
        toolchain_state=toolchain_state,
        machine_validation_state=machine_state,
        companion_state=companion_state,
        config_digest=record.config_digest,
        toolchain_evidence_digest=record.toolchain_evidence_digest,
        machine_evidence_digest=record.machine_evidence_digest,
        readiness_digest=record.readiness_digest,
        readiness_status=record.readiness_status,
        playbook_version=record.playbook_version,
        inventory_version=record.inventory_version,
        companion_artifact_digest=stored.artifact_digest,
        companion_record_digest=record.record_digest,
        observation_generation=record.observation_generation,
        observation_manifest_digest=record.observation_manifest_digest,
        inventory_generation=record.inventory_generation,
        inventory_digest=record.inventory_digest,
        trust_generation=record.trust_generation,
        trust_artifact_digest=record.trust_artifact_digest,
        host_count=record.host_count,
        group_count=record.group_count,
        direct_host_count=record.direct_host_count,
        proxied_host_count=record.proxied_host_count,
        jump_host_count=record.jump_host_count,
        topology_digest=record.topology_digest,
        route_digest=record.route_digest,
        journal_generation=context.deploy.journal.record.generation,
        journal_digest=context.deploy.journal.digest,
        journal_status=context.deploy.journal.record.status,
        journal_phase=context.deploy.journal.record.phase,
        remote_connectivity_status=record.remote_connectivity_status,
        remote_health_status=record.remote_health_status,
        remote_playbook_status=record.remote_playbook_status,
        ansible_deployment_state=_NOT_STARTED,
        finalization_state=_NOT_STARTED,
        runner_invoked=runner_invoked,
        safe_reentry_allowed=True,
        automatic_retry_allowed=True,
        manual_recovery_required=False,
    )


def _record_digest(record: TerraformApplyReadiness) -> str:
    return _record_digest_object(record.to_object())


def _record_digest_object(value: Mapping[str, object]) -> str:
    copied = dict(value)
    copied["record_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(copied))


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _validate_initialized_layout(paths: StatePaths) -> None:
    _require_canonical_paths(paths)
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    for path in (
        paths.cluster_metadata,
        paths.terraform_tfvars,
        paths.terraform_source_record,
        paths.terraform_observed,
        paths.terraform_state,
        paths.ansible_inventory,
    ):
        validate_state_file(path)
    for path in (
        paths.ansible_trust,
        paths.known_hosts,
        paths.ansible_ssh_config,
        paths.ansible_config,
    ):
        validate_state_file(path, allow_missing=True)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if (
        expected != paths
        or paths.terraform_plans.parent != paths.terraform
        or paths.ansible_config.parent != paths.ansible
        or paths.ansible_inventory.parent != paths.ansible
        or paths.ansible_trust.parent != paths.ansible
        or paths.known_hosts.parent != paths.ansible
        or paths.ansible_ssh_config.parent != paths.ansible
        or paths.ansible_log.parent != paths.logs
    ):
        raise UnsafePathError("Terraform apply readiness paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform apply readiness requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    allowed_operation = {paths.operations / f"{operation_id}.json"}
    _refuse_matching_unknown(
        paths.operations,
        operation_id,
        allowed_operation,
        "Terraform apply readiness operation history",
    )
    allowed_plan = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-authorization.json",
        paths.terraform_plans / f"{operation_id}.terraform-state-safeguard.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-execution.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-verification.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-inventory.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-trust.json",
        terraform_apply_readiness_path(paths, operation_id),
    }
    _refuse_matching_unknown(
        paths.terraform_plans,
        operation_id,
        allowed_plan,
        "Terraform apply readiness plan history",
    )
    allowed_backup = {paths.terraform_backups / f"{operation_id}.terraform.tfstate"}
    _refuse_matching_unknown(
        paths.terraform_backups,
        operation_id,
        allowed_backup,
        "Terraform apply readiness backup history",
    )


def _refuse_matching_unknown(
    directory: Path,
    operation_id: uuid.UUID,
    allowed: set[Path],
    label: str,
) -> None:
    try:
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise StatePersistenceError(f"cannot safely list {label}") from error
    for entry in entries:
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry not in allowed:
            raise StateConflictError(f"{label} is ambiguous")


__all__ = [
    "ANSIBLE_INVENTORY_MACHINE_EVIDENCE_SCHEMA_VERSION",
    "TERRAFORM_APPLY_READINESS_FILENAME_SUFFIX",
    "TERRAFORM_APPLY_READINESS_REPORT_SCHEMA_VERSION",
    "TERRAFORM_APPLY_READINESS_SCHEMA_VERSION",
    "StoredTerraformApplyReadiness",
    "TerraformApplyReadiness",
    "TerraformApplyReadinessCompanionState",
    "TerraformApplyReadinessReport",
    "TerraformApplyReadinessStageState",
    "TerraformApplyReadinessStore",
    "terraform_apply_readiness_path",
    "validate_deploy_ansible_readiness",
]
