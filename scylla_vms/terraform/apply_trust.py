"""Operation-bound SSH trust establishment after verified deploy inventory."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.readiness import READINESS_SCHEMA_VERSION
from scylla_vms.ansible.routed_keyscan import (
    ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION,
    ROUTED_KEYSCAN_PORT,
    RoutedCandidateStatus,
    RoutedHostKeyCandidateCollection,
    routed_keyscan_route_digest,
)
from scylla_vms.ansible.trust import (
    APPROVED_HOST_KEY_ALGORITHMS,
    TRUST_SCHEMA_VERSION,
    HostKeyCandidate,
    StoredTrustRecord,
    TrustCaptureSource,
    TrustConfirmation,
    TrustedHostKey,
    TrustRecord,
    TrustStore,
    confirm_host_key_candidate,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import (
    INVENTORY_SCHEMA_VERSION,
    InventoryHost,
    InventoryStore,
    StoredInventoryRecord,
)
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    JournalStatus,
    OperationPhase,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import (
    OBSERVED_STATE_SCHEMA_VERSION,
    StoredObservedState,
)
from scylla_vms.persistence import (
    AtomicJsonFile,
    StoredClusterMetadata,
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
from scylla_vms.terraform.apply_inventory import (
    TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION,
    StoredTerraformApplyInventory,
    TerraformApplyInventoryStore,
    _load_context,
)
from scylla_vms.terraform.apply_verification import (
    TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION,
    StoredTerraformApplyVerification,
)
from scylla_vms.terraform.outputs import MAXIMUM_HOSTS
from scylla_vms.terraform.source import (
    TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION,
    StoredTerraformSource,
)

TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-trust-proof/v1"
)
TERRAFORM_APPLY_TRUST_SCHEMA_VERSION = "deploy-scylla-vms.terraform-apply-trust/v1"
TERRAFORM_APPLY_TRUST_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-trust-report/v1"
)
TERRAFORM_APPLY_TRUST_FILENAME_SUFFIX = ".terraform-apply-trust.json"

_OPERATION = "deploy"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_MAXIMUM_CANDIDATES = MAXIMUM_HOSTS * len(APPROVED_HOST_KEY_ALGORITHMS)
_MAXIMUM_RUNTIME_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TerraformApplyTrustProof:
    """One normalized per-candidate first-trust or revalidation proof."""

    logical_id: str
    algorithm: str
    confirmation: TrustConfirmation
    expected_fingerprint: str | None = None
    schema_version: str = TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION
            or not isinstance(self.logical_id, str)
            or not _LOGICAL_ID.fullmatch(self.logical_id)
            or self.algorithm not in APPROVED_HOST_KEY_ALGORITHMS
            or not isinstance(self.confirmation, TrustConfirmation)
        ):
            raise StatePersistenceError("Terraform apply SSH trust proof is invalid")
        if self.confirmation is TrustConfirmation.EXPLICIT_OPERATOR:
            if self.expected_fingerprint is not None:
                raise StatePersistenceError(
                    "explicit SSH trust proof must not carry a fingerprint"
                )
        elif self.confirmation is TrustConfirmation.EXPECTED_FINGERPRINT and (
            not isinstance(self.expected_fingerprint, str)
            or not _FINGERPRINT.fullmatch(self.expected_fingerprint)
        ):
            raise StatePersistenceError(
                "independent SSH fingerprint proof is malformed"
            )


class TerraformApplyTrustStage(StrEnum):
    JUMP_TRUST_CURRENT = "jump-trust-current"
    COMPLETE = "complete"


class TerraformApplyTrustNextStep(StrEnum):
    PRIVATE_TRUST_PENDING = "private-trust-pending"
    MACHINE_VALIDATION_REQUIRED = "machine-inventory-validation-required"


class TerraformApplyTrustState(StrEnum):
    CREATED = "created"
    ADVANCED = "advanced"
    REVALIDATED = "revalidated"
    REUSED = "reused"


class TerraformApplyTrustDerivativeState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    RECOVERED = "recovered"
    CURRENT = "current"


class TerraformApplyTrustCompanionState(StrEnum):
    NOT_CREATED = "not-created"
    CREATED = "created"
    REUSED = "reused"


class TerraformApplyTrustProofStatus(StrEnum):
    ACCEPTED = "accepted"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class TerraformApplyTrust:
    """Immutable redacted binding for complete operation-scoped SSH trust."""

    generation: int
    completed_at: str
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
    confirmation_proof_digest: str
    host_count: int
    jump_host_count: int
    private_host_count: int
    route_digest: str
    known_hosts_digest: str
    ssh_config_digest: str
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    verification_schema_version: str = TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
    apply_inventory_schema_version: str = TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
    source_schema_version: str = TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
    observation_schema_version: str = OBSERVED_STATE_SCHEMA_VERSION
    inventory_schema_version: str = INVENTORY_SCHEMA_VERSION
    trust_schema_version: str = TRUST_SCHEMA_VERSION
    proof_schema_version: str = TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_TRUST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_TRUST_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.verification_schema_version
            != TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
            or self.apply_inventory_schema_version
            != TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
            or self.source_schema_version != TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
            or self.observation_schema_version != OBSERVED_STATE_SCHEMA_VERSION
            or self.inventory_schema_version != INVENTORY_SCHEMA_VERSION
            or self.trust_schema_version != TRUST_SCHEMA_VERSION
            or self.proof_schema_version != TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION
            or self.generation != 1
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or self.operation != _OPERATION
        ):
            raise StatePersistenceError("unsupported Terraform apply SSH trust record")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.completed_at)
        for generation_value in (
            self.journal_generation,
            self.verification_generation,
            self.apply_inventory_generation,
            self.metadata_generation,
            self.source_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.host_count,
        ):
            if (
                isinstance(generation_value, bool)
                or not isinstance(generation_value, int)
                or generation_value < 1
            ):
                raise StatePersistenceError(
                    "Terraform apply SSH trust generation or count is invalid"
                )
        for host_count in (self.jump_host_count, self.private_host_count):
            if (
                isinstance(host_count, bool)
                or not isinstance(host_count, int)
                or host_count < 0
            ):
                raise StatePersistenceError(
                    "Terraform apply SSH trust host count is invalid"
                )
        if (
            self.host_count > MAXIMUM_HOSTS
            or self.jump_host_count > self.host_count
            or self.private_host_count > self.host_count
            or self.jump_host_count + self.private_host_count != self.host_count
            or not self.source_version
        ):
            raise StatePersistenceError("Terraform apply SSH trust summary is invalid")
        for label, digest_value in (
            ("operation request", self.request_digest),
            ("journal", self.journal_digest),
            ("verification artifact", self.verification_artifact_digest),
            ("verification record", self.verification_record_digest),
            ("apply inventory artifact", self.apply_inventory_artifact_digest),
            ("apply inventory record", self.apply_inventory_record_digest),
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
            ("confirmation proof", self.confirmation_proof_digest),
            ("route", self.route_digest),
            ("known hosts", self.known_hosts_digest),
            ("SSH config", self.ssh_config_digest),
            ("record", self.record_digest),
        ):
            validate_digest(digest_value, f"Terraform apply SSH trust {label} digest")
        if self.record_digest != _companion_digest(self):
            raise StatePersistenceError(
                "Terraform apply SSH trust record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            field: (str(value) if isinstance(value, uuid.UUID) else value)
            for field, value in (
                (name, getattr(self, name)) for name in self.__dataclass_fields__
            )
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformApplyTrust:
        require_exact_keys(
            value,
            set(TerraformApplyTrust.__dataclass_fields__),
            "Terraform apply SSH trust record",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "verification_generation",
            "apply_inventory_generation",
            "metadata_generation",
            "source_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "host_count",
            "jump_host_count",
            "private_host_count",
        }
        parsed: dict[str, object] = {}
        for name in TerraformApplyTrust.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
            elif name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredTerraformApplyTrust:
    record: TerraformApplyTrust
    artifact_digest: str


class TerraformApplyTrustStore:
    """Owner-only immutable complete-trust operation companion."""

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
                "Terraform apply SSH trust operation ID must be a UUID"
            )
        self._paths = paths
        self._operation_id = operation_id
        self._path = terraform_apply_trust_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredTerraformApplyTrust:
        value, artifact_digest = self._file.read()
        record = TerraformApplyTrust.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != _OPERATION
        ):
            raise StatePersistenceError("Terraform apply SSH trust identity conflicts")
        return StoredTerraformApplyTrust(record, artifact_digest)

    def write_locked(
        self,
        record: TerraformApplyTrust,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredTerraformApplyTrust:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Terraform apply SSH trust operation ID conflicts"
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
                    "Terraform apply SSH trust changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Terraform apply SSH trust is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Terraform apply SSH trust requires generation one"
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredTerraformApplyTrust(record, digest)


@dataclass(frozen=True, slots=True)
class TerraformApplyTrustReport:
    """Strict redacted report for one staged or complete trust call."""

    operation_id: uuid.UUID
    stage: TerraformApplyTrustStage
    next_step: TerraformApplyTrustNextStep
    trust_state: TerraformApplyTrustState
    derivative_state: TerraformApplyTrustDerivativeState
    companion_state: TerraformApplyTrustCompanionState
    proof_status: TerraformApplyTrustProofStatus
    proof_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    companion_artifact_digest: str | None
    companion_record_digest: str | None
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    source_generation: int
    source_artifact_digest: str
    source_bundle_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    host_count: int
    trusted_host_count: int
    jump_host_count: int
    private_host_count: int
    route_digest: str
    recovered_partial_state: bool
    safe_reentry_allowed: bool
    automatic_retry_allowed: bool
    manual_recovery_required: bool
    source_status: str
    machine_validation_state: str
    readiness_state: str
    ansible_state: str
    finalization_state: str
    trust_schema_version: str = TRUST_SCHEMA_VERSION
    proof_schema_version: str = TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION
    companion_schema_version: str = TERRAFORM_APPLY_TRUST_SCHEMA_VERSION
    inventory_schema_version: str = INVENTORY_SCHEMA_VERSION
    observation_schema_version: str = OBSERVED_STATE_SCHEMA_VERSION
    source_schema_version: str = TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_TRUST_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        complete = self.stage is TerraformApplyTrustStage.COMPLETE
        if (
            self.schema_version != TERRAFORM_APPLY_TRUST_REPORT_SCHEMA_VERSION
            or self.trust_schema_version != TRUST_SCHEMA_VERSION
            or self.proof_schema_version != TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION
            or self.companion_schema_version != TERRAFORM_APPLY_TRUST_SCHEMA_VERSION
            or self.inventory_schema_version != INVENTORY_SCHEMA_VERSION
            or self.observation_schema_version != OBSERVED_STATE_SCHEMA_VERSION
            or self.source_schema_version != TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.stage, TerraformApplyTrustStage)
            or not isinstance(self.next_step, TerraformApplyTrustNextStep)
            or complete
            != (
                self.next_step
                is TerraformApplyTrustNextStep.MACHINE_VALIDATION_REQUIRED
            )
            or (self.companion_state is TerraformApplyTrustCompanionState.NOT_CREATED)
            == complete
            or (self.companion_artifact_digest is None) == complete
            or (self.companion_record_digest is None) == complete
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.source_status != "current"
            or self.machine_validation_state != "not-performed"
            or self.readiness_state != "not-performed"
            or self.ansible_state != "not-started"
            or self.finalization_state != "not-started"
            or not self.safe_reentry_allowed
            or self.automatic_retry_allowed
            or self.manual_recovery_required
        ):
            raise StatePersistenceError("Terraform apply SSH trust report is invalid")
        for generation_value in (
            self.trust_generation,
            self.inventory_generation,
            self.observation_generation,
            self.source_generation,
            self.journal_generation,
            self.host_count,
            self.trusted_host_count,
        ):
            if (
                isinstance(generation_value, bool)
                or not isinstance(generation_value, int)
                or generation_value < 1
            ):
                raise StatePersistenceError(
                    "Terraform apply SSH trust report count is invalid"
                )
        if (
            self.host_count > MAXIMUM_HOSTS
            or self.trusted_host_count > self.host_count
            or self.jump_host_count < 0
            or self.private_host_count < 0
            or self.jump_host_count + self.private_host_count != self.host_count
        ):
            raise StatePersistenceError(
                "Terraform apply SSH trust report summary is invalid"
            )
        for digest_value in (
            self.proof_digest,
            self.trust_artifact_digest,
            self.trust_entries_digest,
            self.inventory_artifact_digest,
            self.inventory_digest,
            self.observation_artifact_digest,
            self.observation_manifest_digest,
            self.source_artifact_digest,
            self.source_bundle_digest,
            self.journal_digest,
            self.route_digest,
        ):
            validate_digest(digest_value, "Terraform apply SSH trust report digest")
        for optional_digest in (
            self.companion_artifact_digest,
            self.companion_record_digest,
        ):
            if optional_digest is not None:
                validate_digest(
                    optional_digest, "Terraform apply SSH trust companion digest"
                )

    def to_object(self) -> dict[str, object]:
        return {
            "companion": {
                "artifact_digest": self.companion_artifact_digest,
                "record_digest": self.companion_record_digest,
                "schema_version": self.companion_schema_version,
                "state": self.companion_state.value,
            },
            "derivatives": {"state": self.derivative_state.value},
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "schema_version": self.journal_schema_version,
                "status": self.journal_status.value,
            },
            "next_step": self.next_step.value,
            "operation": {"id": str(self.operation_id), "kind": _OPERATION},
            "pending": {
                "ansible": self.ansible_state,
                "finalization": self.finalization_state,
                "machine_validation": self.machine_validation_state,
                "readiness": self.readiness_state,
            },
            "proof": {
                "digest": self.proof_digest,
                "schema_version": self.proof_schema_version,
                "status": self.proof_status.value,
            },
            "provenance": {
                "inventory": {
                    "artifact_digest": self.inventory_artifact_digest,
                    "digest": self.inventory_digest,
                    "generation": self.inventory_generation,
                    "schema_version": self.inventory_schema_version,
                },
                "observation": {
                    "artifact_digest": self.observation_artifact_digest,
                    "generation": self.observation_generation,
                    "manifest_digest": self.observation_manifest_digest,
                    "schema_version": self.observation_schema_version,
                },
                "source": {
                    "artifact_digest": self.source_artifact_digest,
                    "bundle_digest": self.source_bundle_digest,
                    "generation": self.source_generation,
                    "schema_version": self.source_schema_version,
                    "status": self.source_status,
                },
            },
            "recovery": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "manual_recovery_required": self.manual_recovery_required,
                "recovered_partial_state": self.recovered_partial_state,
                "safe_reentry_allowed": self.safe_reentry_allowed,
            },
            "schema_version": self.schema_version,
            "stage": self.stage.value,
            "summary": {
                "host_count": self.host_count,
                "jump_host_count": self.jump_host_count,
                "private_host_count": self.private_host_count,
                "route_digest": self.route_digest,
                "trusted_host_count": self.trusted_host_count,
            },
            "trust": {
                "artifact_digest": self.trust_artifact_digest,
                "entries_digest": self.trust_entries_digest,
                "generation": self.trust_generation,
                "schema_version": self.trust_schema_version,
                "state": self.trust_state.value,
            },
        }


@dataclass(frozen=True, slots=True)
class _TrustContext:
    metadata: StoredClusterMetadata
    journal: StoredOperationRecord
    verification: StoredTerraformApplyVerification
    apply_inventory: StoredTerraformApplyInventory
    source: StoredTerraformSource
    observation: StoredObservedState
    inventory: StoredInventoryRecord


def establish_deploy_ssh_trust(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    direct_candidates: tuple[HostKeyCandidate, ...],
    routed_candidate_collections: tuple[RoutedHostKeyCandidateCollection, ...],
    proofs: tuple[TerraformApplyTrustProof, ...],
) -> TerraformApplyTrustReport:
    """Establish or explicitly revalidate trust without collecting candidates."""

    _validate_api_inputs(
        operation_id, direct_candidates, routed_candidate_collections, proofs
    )
    paths = StatePaths.derive(state_root, cluster_name)
    _assert_operation_lock(lock, paths)
    _validate_initialized_layout(paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_trust_context(paths, operation_id)
    store = TerraformApplyTrustStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    companion_exists = store.path.exists()
    trust_store = TrustStore(paths)
    trust = _read_optional_trust(paths, context)

    if trust is None:
        if companion_exists:
            raise StateConflictError(
                "Terraform apply SSH trust companion exists without trust"
            )
        _require_absent_runtime(paths)
    else:
        _validate_trust_semantics(trust, context)

    recovered = False
    if trust is not None:
        if companion_exists:
            trust_store.validate_runtime(trust, context.inventory)
        else:
            recovered = _recover_missing_runtime(
                paths, trust_store, trust, context.inventory, lock
            )

    hosts = {host.logical_id: host for host in context.inventory.record.inventory.hosts}
    trusted = (
        {entry.logical_id: entry for entry in trust.record.entries}
        if trust is not None
        else {}
    )
    fresh = trust is not None and trust.record.is_fresh_for(
        context.observation.record, context.inventory.record
    )
    replayed_ids = _replayed_target_ids(direct_candidates, routed_candidate_collections)

    if (
        trust is not None
        and fresh
        and (
            len(trusted) == len(hosts)
            or (replayed_ids and replayed_ids <= set(trusted))
        )
    ):
        _validate_complete_reentry_inputs(
            context,
            trust,
            direct_candidates,
            routed_candidate_collections,
            proofs,
        )
        stored_trust = trust
        trust_state = TerraformApplyTrustState.REUSED
        derivative_state = (
            TerraformApplyTrustDerivativeState.RECOVERED
            if recovered
            else TerraformApplyTrustDerivativeState.CURRENT
        )
        proof_status = TerraformApplyTrustProofStatus.REUSED
    elif trust is not None and not fresh:
        if len(trusted) != len(hosts):
            raise StateConflictError(
                "stale partial SSH trust cannot be implicitly revalidated"
            )
        if direct_candidates or routed_candidate_collections:
            raise StateConflictError(
                "SSH trust revalidation does not accept replacement candidates"
            )
        _validate_revalidation_proofs(trust, proofs)
        target = TrustRecord.create(
            context.observation.record,
            context.inventory.record,
            trust.record.entries,
            generation=trust.record.generation + 1,
        )
        _reload_exact_context(paths, operation_id, context, trust)
        trust_store.prepare_runtime_transition_locked(
            trust, context.inventory, lock=lock
        )
        stored_trust = trust_store.write_locked(
            target,
            context.observation,
            context.inventory,
            approved=True,
            expected_generation=trust.record.generation,
            expected_digest=trust.digest,
            lock=lock,
        )
        trust_state = TerraformApplyTrustState.REVALIDATED
        derivative_state = TerraformApplyTrustDerivativeState.UPDATED
        proof_status = TerraformApplyTrustProofStatus.ACCEPTED
    else:
        missing = set(hosts) - set(trusted)
        direct_missing = {
            logical_id
            for logical_id in missing
            if hosts[logical_id].jump_host_id is None
        }
        if direct_missing:
            if routed_candidate_collections:
                raise StateConflictError(
                    "untrusted jump and routed private candidates cannot be "
                    "established simultaneously"
                )
            selected = _confirm_direct_candidates(
                context, direct_candidates, proofs, direct_missing
            )
        else:
            if direct_candidates:
                raise StateConflictError(
                    "private SSH trust accepts only routed candidate collections"
                )
            if trust is None:
                raise StateConflictError(
                    "routed private SSH trust requires already-current jump trust"
                )
            selected = _confirm_routed_candidates(
                context,
                trust,
                routed_candidate_collections,
                proofs,
                missing,
            )
        entries = tuple(
            sorted((*trusted.values(), *selected), key=lambda item: item.logical_id)
        )
        generation = 1 if trust is None else trust.record.generation + 1
        target = TrustRecord.create(
            context.observation.record,
            context.inventory.record,
            entries,
            generation=generation,
        )
        _reload_exact_context(paths, operation_id, context, trust)
        if trust is not None:
            trust_store.prepare_runtime_transition_locked(
                trust, context.inventory, lock=lock
            )
        stored_trust = trust_store.write_locked(
            target,
            context.observation,
            context.inventory,
            approved=True,
            expected_generation=0 if trust is None else trust.record.generation,
            expected_digest=None if trust is None else trust.digest,
            lock=lock,
        )
        trust_state = (
            TerraformApplyTrustState.CREATED
            if trust is None
            else TerraformApplyTrustState.ADVANCED
        )
        derivative_state = (
            TerraformApplyTrustDerivativeState.CREATED
            if trust is None
            else TerraformApplyTrustDerivativeState.UPDATED
        )
        proof_status = TerraformApplyTrustProofStatus.ACCEPTED

    _reload_exact_context(paths, operation_id, context, stored_trust)
    trust_store.validate_runtime(stored_trust, context.inventory)
    complete = len(stored_trust.record.entries) == len(hosts)
    proof_digest = _proof_digest(stored_trust.record.entries)
    stored_companion: StoredTerraformApplyTrust | None = None
    if complete:
        completed_at = (
            TerraformApplyTrustStore(paths, operation_id)
            .read(
                expected_cluster_uuid=context.metadata.record.cluster_uuid,
                expected_cluster_name=context.metadata.record.cluster_name,
            )
            .record.completed_at
            if companion_exists
            else format_timestamp(datetime.now(UTC))
        )
        expected = _create_companion(
            paths,
            context,
            stored_trust,
            completed_at=completed_at,
            proof_digest=proof_digest,
        )
        if companion_exists:
            stored_companion = store.read(
                expected_cluster_uuid=context.metadata.record.cluster_uuid,
                expected_cluster_name=context.metadata.record.cluster_name,
            )
            if stored_companion.record != expected:
                raise StateConflictError(
                    "Terraform apply SSH trust companion binding changed"
                )
            companion_state = TerraformApplyTrustCompanionState.REUSED
        else:
            stored_companion = store.write_locked(
                expected,
                expected_generation=0,
                expected_digest=None,
                lock=lock,
            )
            companion_state = TerraformApplyTrustCompanionState.CREATED
        _reload_exact_context(paths, operation_id, context, stored_trust)
        trust_store.validate_runtime(stored_trust, context.inventory)
        stage = TerraformApplyTrustStage.COMPLETE
        next_step = TerraformApplyTrustNextStep.MACHINE_VALIDATION_REQUIRED
    else:
        if companion_exists:
            raise StateConflictError(
                "Terraform apply SSH trust companion exists before complete trust"
            )
        _require_jump_stage(context.inventory, stored_trust)
        companion_state = TerraformApplyTrustCompanionState.NOT_CREATED
        stage = TerraformApplyTrustStage.JUMP_TRUST_CURRENT
        next_step = TerraformApplyTrustNextStep.PRIVATE_TRUST_PENDING

    return _report(
        context,
        stored_trust,
        stored_companion,
        stage=stage,
        next_step=next_step,
        trust_state=trust_state,
        derivative_state=derivative_state,
        companion_state=companion_state,
        proof_status=proof_status,
        proof_digest=proof_digest,
        recovered=recovered,
    )


def terraform_apply_trust_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    """Return the sole canonical operation trust companion path."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply SSH trust operation ID must be a UUID"
        )
    path = (
        paths.terraform_plans / f"{operation_id}{TERRAFORM_APPLY_TRUST_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform apply SSH trust path is not canonical")
    return path


def _load_trust_context(paths: StatePaths, operation_id: uuid.UUID) -> _TrustContext:
    base = _load_context(paths, operation_id)
    inventory = InventoryStore(paths).read(
        expected_cluster_uuid=base.metadata.record.cluster_uuid,
        expected_cluster_name=base.metadata.record.cluster_name,
        expected_provider=base.metadata.record.provider,
    )
    apply_inventory_path = (
        paths.terraform_plans / f"{operation_id}.terraform-apply-inventory.json"
    )
    validate_state_file(apply_inventory_path, allow_missing=True)
    if not apply_inventory_path.exists():
        raise StateConflictError(
            "Terraform apply SSH trust requires verified deploy inventory"
        )
    apply_inventory = TerraformApplyInventoryStore(paths, operation_id).read(
        expected_cluster_uuid=base.metadata.record.cluster_uuid,
        expected_cluster_name=base.metadata.record.cluster_name,
    )
    context = _TrustContext(
        base.metadata,
        base.journal,
        base.verification,
        apply_inventory,
        base.source,
        base.observation,
        inventory,
    )
    _require_inventory_companion(context)
    return context


def _require_inventory_companion(context: _TrustContext) -> None:
    record = context.apply_inventory.record
    verification = context.verification.record
    metadata = context.metadata
    source = context.source
    observation = context.observation
    inventory = context.inventory
    if (
        record.operation_id != verification.operation_id
        or record.operation != _OPERATION
        or record.cluster_uuid != metadata.record.cluster_uuid
        or record.cluster_name != metadata.record.cluster_name
        or record.request_digest != context.journal.record.request_digest
        or record.journal_generation != context.journal.record.generation
        or record.journal_digest != context.journal.digest
        or record.verification_generation != verification.generation
        or record.verification_artifact_digest != context.verification.artifact_digest
        or record.verification_record_digest != verification.record_digest
        or record.metadata_generation != metadata.record.generation
        or record.metadata_digest != metadata.digest
        or record.desired_spec_digest != metadata.record.desired_spec.digest()
        or record.source_generation != source.record.generation
        or record.source_digest != source.digest
        or record.source_version != source.record.source_version
        or record.source_bundle_digest != source.record.bundle_digest
        or record.observation_generation != observation.record.generation
        or record.observation_artifact_digest != observation.digest
        or record.observation_manifest_digest != observation.record.manifest_digest
        or record.inventory_generation != inventory.record.generation
        or record.inventory_artifact_digest != inventory.digest
        or record.inventory_digest != inventory.record.inventory_digest
        or record.host_count != len(inventory.record.inventory.hosts)
        or record.route_digest != _route_digest(inventory)
    ):
        raise StateConflictError(
            "Terraform apply SSH trust inventory binding is stale or conflicting"
        )


def _read_optional_trust(
    paths: StatePaths, context: _TrustContext
) -> StoredTrustRecord | None:
    validate_state_file(paths.ansible_trust, allow_missing=True)
    if not paths.ansible_trust.exists():
        return None
    return TrustStore(paths).read(
        expected_cluster_uuid=context.metadata.record.cluster_uuid,
        expected_cluster_name=context.metadata.record.cluster_name,
        expected_provider=context.metadata.record.provider,
    )


def _validate_trust_semantics(trust: StoredTrustRecord, context: _TrustContext) -> None:
    record = trust.record
    hosts = {host.logical_id: host for host in context.inventory.record.inventory.hosts}
    for entry in record.entries:
        host = hosts.get(entry.logical_id)
        if host is None or not _entry_matches_host(entry, host):
            raise StateConflictError(
                "SSH trust identity, endpoint, provider, or route conflicts"
            )
    if (
        record.cluster_uuid != context.metadata.record.cluster_uuid
        or record.cluster_name != context.metadata.record.cluster_name
        or record.provider != context.metadata.record.provider
        or record.observation_generation > context.observation.record.generation
        or record.inventory_generation > context.inventory.record.generation
        or (
            record.observation_generation == context.observation.record.generation
            and record.observation_digest != context.observation.record.manifest_digest
        )
        or (
            record.inventory_generation == context.inventory.record.generation
            and record.inventory_digest != context.inventory.record.inventory_digest
        )
    ):
        raise StateConflictError(
            "SSH trust provenance conflicts with verified deploy inventory"
        )


def _confirm_direct_candidates(
    context: _TrustContext,
    candidates: tuple[HostKeyCandidate, ...],
    proofs: tuple[TerraformApplyTrustProof, ...],
    required_ids: set[str],
) -> tuple[TrustedHostKey, ...]:
    if not candidates:
        raise StateConflictError("direct SSH trust candidates are missing")
    grouped = _validate_candidates(context, candidates, required_ids, routed=False)
    return _confirm_selected(grouped, proofs, required_ids)


def _confirm_routed_candidates(
    context: _TrustContext,
    trust: StoredTrustRecord,
    collections: tuple[RoutedHostKeyCandidateCollection, ...],
    proofs: tuple[TerraformApplyTrustProof, ...],
    required_ids: set[str],
) -> tuple[TrustedHostKey, ...]:
    if not collections:
        raise StateConflictError("routed private SSH trust candidates are missing")
    candidates: list[HostKeyCandidate] = []
    selected_ids: set[str] = set()
    hosts = {host.logical_id: host for host in context.inventory.record.inventory.hosts}
    trusted_ids = {entry.logical_id for entry in trust.record.entries}
    for collection in collections:
        _validate_routed_collection_policy(collection)
        if (
            collection.observation_generation != context.observation.record.generation
            or collection.observation_digest
            != context.observation.record.manifest_digest
            or collection.inventory_generation != context.inventory.record.generation
            or collection.inventory_digest != context.inventory.digest
            or collection.trust_generation != trust.record.generation
            or collection.trust_digest != trust.digest
            or tuple(sorted(set(collection.jump_host_ids))) != collection.jump_host_ids
            or not collection.targets
        ):
            raise StateConflictError(
                "routed SSH candidate collection provenance conflicts"
            )
        parse_timestamp(collection.captured_at)
        if parse_timestamp(collection.captured_at) < parse_timestamp(
            context.observation.record.captured_at
        ):
            raise StateConflictError("routed SSH candidate collection is stale")
        for jump_id in collection.jump_host_ids:
            jump = hosts.get(jump_id)
            if (
                jump is None
                or jump.role is not HostRole.JUMP_HOST
                or jump.jump_host_id is not None
                or jump_id not in trusted_ids
            ):
                raise StateConflictError(
                    "routed SSH candidate jump trust is not current"
                )
        target_ids = tuple(target.logical_id for target in collection.targets)
        if target_ids != tuple(sorted(set(target_ids))) or {
            target.jump_host_id for target in collection.targets
        } != set(collection.jump_host_ids):
            raise StateConflictError(
                "routed SSH candidate target or jump set conflicts"
            )
        for target in collection.targets:
            host = hosts.get(target.logical_id)
            jump = hosts.get(target.jump_host_id)
            if (
                target.logical_id in selected_ids
                or target.logical_id not in required_ids
                or host is None
                or jump is None
                or host.jump_host_id != target.jump_host_id
                or target.jump_host_id not in trusted_ids
                or target.provider_id != host.provider_id
                or target.route_digest != routed_keyscan_route_digest(jump, host)
                or target.status is not RoutedCandidateStatus.COLLECTED
                or not isinstance(target.blockers, tuple)
                or target.blockers
                or not isinstance(target.candidates, tuple)
                or not target.candidates
            ):
                raise StateConflictError(
                    "routed SSH candidate target identity or route conflicts"
                )
            selected_ids.add(target.logical_id)
            candidates.extend(target.candidates)
    if selected_ids != required_ids:
        raise StateConflictError(
            "routed SSH candidate host set is incomplete or unexpected"
        )
    grouped = _validate_candidates(
        context, tuple(candidates), required_ids, routed=True
    )
    return _confirm_selected(grouped, proofs, required_ids)


def _validate_routed_collection_policy(
    collection: RoutedHostKeyCandidateCollection,
) -> None:
    if (
        collection.schema_version != ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION
        or collection.status != "collected"
        or collection.readiness_schema_version != READINESS_SCHEMA_VERSION
        or isinstance(collection.timeout_seconds, bool)
        or not isinstance(collection.timeout_seconds, int)
        or not 1 <= collection.timeout_seconds <= 60
        or not isinstance(collection.jump_host_ids, tuple)
        or not isinstance(collection.targets, tuple)
    ):
        raise StateConflictError("routed SSH candidate collection policy conflicts")
    validate_digest(
        collection.readiness_digest, "routed SSH candidate readiness digest"
    )


def _validate_candidates(
    context: _TrustContext,
    candidates: tuple[HostKeyCandidate, ...],
    required_ids: set[str],
    *,
    routed: bool,
) -> dict[str, dict[str, HostKeyCandidate]]:
    if not 1 <= len(candidates) <= _MAXIMUM_CANDIDATES:
        raise StateConflictError("SSH trust candidate count is invalid")
    hosts = {host.logical_id: host for host in context.inventory.record.inventory.hosts}
    grouped: dict[str, dict[str, HostKeyCandidate]] = {}
    identities: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        if not isinstance(candidate, HostKeyCandidate):
            raise StatePersistenceError("SSH trust candidate type is invalid")
        host = hosts.get(candidate.logical_id)
        if (
            candidate.logical_id not in required_ids
            or host is None
            or not _candidate_matches_host(candidate, host)
            or (
                routed
                and candidate.capture_source
                is not TrustCaptureSource.ROUTED_JUMP_KEYSCAN
            )
            or (
                not routed
                and candidate.capture_source is TrustCaptureSource.ROUTED_JUMP_KEYSCAN
            )
            or parse_timestamp(candidate.captured_at)
            < parse_timestamp(context.observation.record.captured_at)
        ):
            raise StateConflictError(
                "SSH trust candidate identity, route, source, or generation conflicts"
            )
        identity = (
            candidate.logical_id,
            candidate.algorithm,
            candidate.fingerprint,
        )
        if identity in identities:
            raise StateConflictError("SSH trust candidates are duplicated")
        identities.add(identity)
        by_algorithm = grouped.setdefault(candidate.logical_id, {})
        if candidate.algorithm in by_algorithm:
            raise StateConflictError(
                "SSH trust candidates conflict for one host algorithm"
            )
        by_algorithm[candidate.algorithm] = candidate
    if set(grouped) != required_ids:
        raise StateConflictError(
            "SSH trust candidate host set is incomplete or unexpected"
        )
    return grouped


def _confirm_selected(
    grouped: dict[str, dict[str, HostKeyCandidate]],
    proofs: tuple[TerraformApplyTrustProof, ...],
    required_ids: set[str],
) -> tuple[TrustedHostKey, ...]:
    proof_by_host: dict[str, TerraformApplyTrustProof] = {}
    for proof in proofs:
        if not isinstance(proof, TerraformApplyTrustProof):
            raise StatePersistenceError("SSH trust proof type is invalid")
        if proof.logical_id in proof_by_host:
            raise StateConflictError("SSH trust proofs are duplicated")
        proof_by_host[proof.logical_id] = proof
    if set(proof_by_host) != required_ids:
        raise StateConflictError(
            "SSH trust requires one exact proof for every candidate host"
        )
    confirmed: list[TrustedHostKey] = []
    now = datetime.now(UTC)
    for logical_id in sorted(required_ids):
        proof = proof_by_host[logical_id]
        candidate = grouped[logical_id].get(proof.algorithm)
        if candidate is None:
            raise StateConflictError(
                "SSH trust proof does not select an obtained candidate"
            )
        confirmed_at = max(now, parse_timestamp(candidate.captured_at))
        confirmed.append(
            confirm_host_key_candidate(
                candidate,
                confirmed_at=confirmed_at,
                explicitly_confirmed=(
                    proof.confirmation is TrustConfirmation.EXPLICIT_OPERATOR
                ),
                expected_fingerprint=proof.expected_fingerprint,
            )
        )
    return tuple(confirmed)


def _validate_revalidation_proofs(
    trust: StoredTrustRecord,
    proofs: tuple[TerraformApplyTrustProof, ...],
) -> None:
    entries = {entry.logical_id: entry for entry in trust.record.entries}
    proof_by_host = _proof_map(proofs)
    if set(proof_by_host) != set(entries):
        raise StateConflictError(
            "stale SSH trust requires one explicit proof for every host"
        )
    for logical_id, entry in entries.items():
        proof = proof_by_host[logical_id]
        if (
            proof.algorithm != entry.algorithm
            or proof.confirmation is not entry.confirmation
            or (
                proof.confirmation is TrustConfirmation.EXPECTED_FINGERPRINT
                and proof.expected_fingerprint != entry.fingerprint
            )
        ):
            raise StateConflictError("SSH trust revalidation proof conflicts")


def _validate_complete_reentry_inputs(
    context: _TrustContext,
    trust: StoredTrustRecord,
    direct: tuple[HostKeyCandidate, ...],
    routed: tuple[RoutedHostKeyCandidateCollection, ...],
    proofs: tuple[TerraformApplyTrustProof, ...],
) -> None:
    if not direct and not routed and not proofs:
        return
    entries = {entry.logical_id: entry for entry in trust.record.entries}
    candidate_values = list(direct)
    routed_ids: set[str] = set()
    hosts = {host.logical_id: host for host in context.inventory.record.inventory.hosts}
    trusted_ids = set(entries)
    routed_source_generation: int | None = None
    routed_source_digest: str | None = None
    if routed:
        if trust.record.generation < 2:
            raise StateConflictError(
                "replayed routed SSH candidate trust provenance conflicts"
            )
        prior_entries = tuple(
            entry for entry in trust.record.entries if entry.jump_host_id is None
        )
        prior = TrustRecord.create(
            context.observation.record,
            context.inventory.record,
            prior_entries,
            generation=trust.record.generation - 1,
        )
        routed_source_generation = prior.generation
        routed_source_digest = digest_bytes(serialize_json(prior.to_object()))
    for candidate in direct:
        host = hosts.get(candidate.logical_id)
        if (
            host is None
            or not _candidate_matches_host(candidate, host)
            or candidate.capture_source is TrustCaptureSource.ROUTED_JUMP_KEYSCAN
            or parse_timestamp(candidate.captured_at)
            < parse_timestamp(context.observation.record.captured_at)
        ):
            raise StateConflictError("replayed direct SSH candidate conflicts")
    for collection in routed:
        _validate_routed_collection_policy(collection)
        if (
            collection.observation_generation != context.observation.record.generation
            or collection.observation_digest
            != context.observation.record.manifest_digest
            or collection.inventory_generation != context.inventory.record.generation
            or collection.inventory_digest != context.inventory.digest
            or collection.trust_generation != routed_source_generation
            or collection.trust_digest != routed_source_digest
            or tuple(sorted(set(collection.jump_host_ids))) != collection.jump_host_ids
            or not collection.targets
        ):
            raise StateConflictError(
                "replayed routed SSH candidate provenance conflicts"
            )
        parse_timestamp(collection.captured_at)
        if parse_timestamp(collection.captured_at) < parse_timestamp(
            context.observation.record.captured_at
        ):
            raise StateConflictError("replayed routed SSH candidate is stale")
        for jump_id in collection.jump_host_ids:
            jump = hosts.get(jump_id)
            if (
                jump is None
                or jump.role is not HostRole.JUMP_HOST
                or jump.jump_host_id is not None
                or jump_id not in trusted_ids
            ):
                raise StateConflictError(
                    "replayed routed SSH candidate jump trust conflicts"
                )
        target_ids = tuple(target.logical_id for target in collection.targets)
        if target_ids != tuple(sorted(set(target_ids))) or {
            target.jump_host_id for target in collection.targets
        } != set(collection.jump_host_ids):
            raise StateConflictError("replayed routed SSH candidate targets conflict")
        for target in collection.targets:
            host = hosts.get(target.logical_id)
            jump = hosts.get(target.jump_host_id)
            if (
                target.logical_id in routed_ids
                or target.logical_id not in entries
                or host is None
                or jump is None
                or host.jump_host_id != target.jump_host_id
                or target.jump_host_id not in trusted_ids
                or target.provider_id != host.provider_id
                or target.route_digest != routed_keyscan_route_digest(jump, host)
                or target.status is not RoutedCandidateStatus.COLLECTED
                or not isinstance(target.blockers, tuple)
                or target.blockers
                or not isinstance(target.candidates, tuple)
                or not target.candidates
            ):
                raise StateConflictError(
                    "replayed routed SSH candidate target conflicts"
                )
            for candidate in target.candidates:
                if (
                    candidate.logical_id != target.logical_id
                    or not _candidate_matches_host(candidate, host)
                    or candidate.capture_source
                    is not TrustCaptureSource.ROUTED_JUMP_KEYSCAN
                    or parse_timestamp(candidate.captured_at)
                    < parse_timestamp(context.observation.record.captured_at)
                ):
                    raise StateConflictError(
                        "replayed routed SSH candidate key conflicts"
                    )
            routed_ids.add(target.logical_id)
            candidate_values.extend(target.candidates)
    proof_by_host = _proof_map(proofs)
    if candidate_values:
        if len(candidate_values) > _MAXIMUM_CANDIDATES:
            raise StateConflictError("replayed SSH trust candidate count is invalid")
        candidate_ids = {candidate.logical_id for candidate in candidate_values}
        if set(proof_by_host) != candidate_ids:
            raise StateConflictError("replayed SSH trust proof set conflicts")
        for candidate in candidate_values:
            host = hosts.get(candidate.logical_id)
            if host is None or not _candidate_matches_host(candidate, host):
                raise StateConflictError("replayed SSH trust candidate conflicts")
        for logical_id, proof in proof_by_host.items():
            entry = entries.get(logical_id)
            matching = [
                candidate
                for candidate in candidate_values
                if candidate.logical_id == logical_id
                and candidate.algorithm == proof.algorithm
            ]
            if (
                entry is None
                or len(matching) != 1
                or not _candidate_matches_entry(matching[0], entry)
                or proof.confirmation is not entry.confirmation
                or (
                    proof.confirmation is TrustConfirmation.EXPECTED_FINGERPRINT
                    and proof.expected_fingerprint != entry.fingerprint
                )
            ):
                raise StateConflictError("replayed SSH trust input conflicts")
    else:
        _validate_revalidation_proofs(trust, proofs)


def _replayed_target_ids(
    direct: tuple[HostKeyCandidate, ...],
    routed: tuple[RoutedHostKeyCandidateCollection, ...],
) -> set[str]:
    return {
        *(candidate.logical_id for candidate in direct),
        *(target.logical_id for collection in routed for target in collection.targets),
    }


def _proof_map(
    proofs: tuple[TerraformApplyTrustProof, ...],
) -> dict[str, TerraformApplyTrustProof]:
    result: dict[str, TerraformApplyTrustProof] = {}
    for proof in proofs:
        if not isinstance(proof, TerraformApplyTrustProof):
            raise StatePersistenceError("SSH trust proof type is invalid")
        if proof.logical_id in result:
            raise StateConflictError("SSH trust proofs are duplicated")
        result[proof.logical_id] = proof
    return result


def _candidate_matches_host(candidate: HostKeyCandidate, host: InventoryHost) -> bool:
    return (
        candidate.provider_id == host.provider_id
        and candidate.endpoint.address == host.ansible_host
        and candidate.endpoint.port == ROUTED_KEYSCAN_PORT
        and candidate.jump_host_id == host.jump_host_id
    )


def _entry_matches_host(entry: TrustedHostKey, host: InventoryHost) -> bool:
    return (
        entry.provider_id == host.provider_id
        and entry.endpoint.address == host.ansible_host
        and entry.endpoint.port == ROUTED_KEYSCAN_PORT
        and entry.jump_host_id == host.jump_host_id
    )


def _candidate_matches_entry(
    candidate: HostKeyCandidate, entry: TrustedHostKey
) -> bool:
    return (
        candidate.logical_id == entry.logical_id
        and candidate.provider_id == entry.provider_id
        and candidate.endpoint == entry.endpoint
        and candidate.jump_host_id == entry.jump_host_id
        and candidate.algorithm == entry.algorithm
        and candidate.public_key == entry.public_key
        and candidate.fingerprint == entry.fingerprint
        and candidate.capture_source is entry.capture_source
    )


def _recover_missing_runtime(
    paths: StatePaths,
    store: TrustStore,
    trust: StoredTrustRecord,
    inventory: StoredInventoryRecord,
    lock: ClusterLock,
) -> bool:
    present = (paths.known_hosts.exists(), paths.ansible_ssh_config.exists())
    if all(present):
        store.validate_runtime(trust, inventory)
        return False
    store.recover_runtime_locked(trust, inventory, lock=lock)
    return True


def _require_absent_runtime(paths: StatePaths) -> None:
    for path in (paths.known_hosts, paths.ansible_ssh_config):
        validate_state_file(path, allow_missing=True)
        if path.exists():
            raise StateConflictError("SSH runtime derivative exists without trust")


def _require_jump_stage(
    inventory: StoredInventoryRecord, trust: StoredTrustRecord
) -> None:
    hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
    trusted = {entry.logical_id for entry in trust.record.entries}
    direct = {host.logical_id for host in hosts.values() if host.jump_host_id is None}
    private = set(hosts) - direct
    if not private or not direct.issubset(trusted) or trusted - direct:
        raise StateConflictError("SSH trust staged dependency state is invalid")


def _reload_exact_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    expected: _TrustContext,
    trust: StoredTrustRecord | None,
) -> None:
    current = _load_trust_context(paths, operation_id)
    if current != expected:
        raise StateConflictError(
            "Terraform apply SSH trust inputs changed during persistence"
        )
    if trust is None:
        validate_state_file(paths.ansible_trust, allow_missing=True)
        if paths.ansible_trust.exists():
            raise StateConflictError("SSH trust appeared concurrently")
        return
    reread = TrustStore(paths).read(
        expected_cluster_uuid=expected.metadata.record.cluster_uuid,
        expected_cluster_name=expected.metadata.record.cluster_name,
        expected_provider=expected.metadata.record.provider,
    )
    if reread != trust:
        raise StateConflictError("SSH trust changed during operation")


def _create_companion(
    paths: StatePaths,
    context: _TrustContext,
    trust: StoredTrustRecord,
    *,
    completed_at: str,
    proof_digest: str,
) -> TerraformApplyTrust:
    hosts = context.inventory.record.inventory.hosts
    values: dict[str, object] = {
        "apply_inventory_artifact_digest": context.apply_inventory.artifact_digest,
        "apply_inventory_generation": context.apply_inventory.record.generation,
        "apply_inventory_record_digest": context.apply_inventory.record.record_digest,
        "apply_inventory_schema_version": context.apply_inventory.record.schema_version,
        "cluster_name": context.metadata.record.cluster_name,
        "cluster_uuid": str(context.metadata.record.cluster_uuid),
        "completed_at": completed_at,
        "confirmation_proof_digest": proof_digest,
        "desired_spec_digest": context.metadata.record.desired_spec.digest(),
        "generation": 1,
        "host_count": len(hosts),
        "inventory_artifact_digest": context.inventory.digest,
        "inventory_digest": context.inventory.record.inventory_digest,
        "inventory_generation": context.inventory.record.generation,
        "inventory_schema_version": context.inventory.record.schema_version,
        "journal_digest": context.journal.digest,
        "journal_generation": context.journal.record.generation,
        "journal_schema_version": context.journal.record.schema_version,
        "jump_host_count": sum(host.role is HostRole.JUMP_HOST for host in hosts),
        "known_hosts_digest": _runtime_file_digest(paths.known_hosts),
        "metadata_digest": context.metadata.digest,
        "metadata_generation": context.metadata.record.generation,
        "observation_artifact_digest": context.observation.digest,
        "observation_generation": context.observation.record.generation,
        "observation_manifest_digest": context.observation.record.manifest_digest,
        "observation_schema_version": context.observation.record.schema_version,
        "operation": _OPERATION,
        "operation_id": str(context.journal.record.operation_id),
        "private_host_count": sum(host.jump_host_id is not None for host in hosts),
        "proof_schema_version": TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION,
        "record_digest": "sha256:" + "0" * 64,
        "request_digest": context.journal.record.request_digest,
        "route_digest": context.apply_inventory.record.route_digest,
        "schema_version": TERRAFORM_APPLY_TRUST_SCHEMA_VERSION,
        "source_artifact_digest": context.source.digest,
        "source_bundle_digest": context.source.record.bundle_digest,
        "source_generation": context.source.record.generation,
        "source_schema_version": context.source.record.schema_version,
        "source_version": context.source.record.source_version,
        "ssh_config_digest": _runtime_file_digest(paths.ansible_ssh_config),
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "trust_generation": trust.record.generation,
        "trust_schema_version": trust.record.schema_version,
        "verification_artifact_digest": context.verification.artifact_digest,
        "verification_generation": context.verification.record.generation,
        "verification_record_digest": context.verification.record.record_digest,
        "verification_schema_version": context.verification.record.schema_version,
    }
    values["record_digest"] = _companion_digest_object(values)
    return TerraformApplyTrust.from_object(values)


def _runtime_file_digest(path: Path) -> str:
    validate_state_file(path)
    data = path.read_bytes()
    if len(data) > _MAXIMUM_RUNTIME_BYTES:
        raise StatePersistenceError("SSH runtime derivative exceeds size limit")
    return digest_bytes(data)


def _proof_digest(entries: tuple[TrustedHostKey, ...]) -> str:
    values = [
        {
            "algorithm": entry.algorithm,
            "confirmation": entry.confirmation.value,
            "fingerprint": entry.fingerprint,
            "logical_id": entry.logical_id,
        }
        for entry in entries
    ]
    return digest_bytes(serialize_json({"proofs": cast(object, values)}))


def _route_digest(inventory: StoredInventoryRecord) -> str:
    values = [
        {
            "jump_host_id": host.jump_host_id,
            "logical_id": host.logical_id,
            "mode": host.route_mode,
        }
        for host in inventory.record.inventory.hosts
    ]
    return digest_bytes(serialize_json({"routes": cast(object, values)}))


def _companion_digest(record: TerraformApplyTrust) -> str:
    return _companion_digest_object(record.to_object())


def _companion_digest_object(value: Mapping[str, object]) -> str:
    copied = dict(value)
    copied["record_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(copied))


def _report(
    context: _TrustContext,
    trust: StoredTrustRecord,
    companion: StoredTerraformApplyTrust | None,
    *,
    stage: TerraformApplyTrustStage,
    next_step: TerraformApplyTrustNextStep,
    trust_state: TerraformApplyTrustState,
    derivative_state: TerraformApplyTrustDerivativeState,
    companion_state: TerraformApplyTrustCompanionState,
    proof_status: TerraformApplyTrustProofStatus,
    proof_digest: str,
    recovered: bool,
) -> TerraformApplyTrustReport:
    hosts = context.inventory.record.inventory.hosts
    return TerraformApplyTrustReport(
        operation_id=context.journal.record.operation_id,
        stage=stage,
        next_step=next_step,
        trust_state=trust_state,
        derivative_state=derivative_state,
        companion_state=companion_state,
        proof_status=proof_status,
        proof_digest=proof_digest,
        trust_generation=trust.record.generation,
        trust_artifact_digest=trust.digest,
        trust_entries_digest=trust.record.entries_digest,
        companion_artifact_digest=(
            companion.artifact_digest if companion is not None else None
        ),
        companion_record_digest=(
            companion.record.record_digest if companion is not None else None
        ),
        inventory_generation=context.inventory.record.generation,
        inventory_artifact_digest=context.inventory.digest,
        inventory_digest=context.inventory.record.inventory_digest,
        observation_generation=context.observation.record.generation,
        observation_artifact_digest=context.observation.digest,
        observation_manifest_digest=context.observation.record.manifest_digest,
        source_generation=context.source.record.generation,
        source_artifact_digest=context.source.digest,
        source_bundle_digest=context.source.record.bundle_digest,
        journal_generation=context.journal.record.generation,
        journal_digest=context.journal.digest,
        journal_status=context.journal.record.status,
        journal_phase=context.journal.record.phase,
        host_count=len(hosts),
        trusted_host_count=len(trust.record.entries),
        jump_host_count=sum(host.role is HostRole.JUMP_HOST for host in hosts),
        private_host_count=sum(host.jump_host_id is not None for host in hosts),
        route_digest=context.apply_inventory.record.route_digest,
        recovered_partial_state=recovered,
        safe_reentry_allowed=True,
        automatic_retry_allowed=False,
        manual_recovery_required=False,
        source_status="current",
        machine_validation_state="not-performed",
        readiness_state="not-performed",
        ansible_state="not-started",
        finalization_state="not-started",
    )


def _validate_api_inputs(
    operation_id: uuid.UUID,
    direct_candidates: tuple[HostKeyCandidate, ...],
    routed_collections: tuple[RoutedHostKeyCandidateCollection, ...],
    proofs: tuple[TerraformApplyTrustProof, ...],
) -> None:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply SSH trust operation ID must be a UUID"
        )
    if (
        not isinstance(direct_candidates, tuple)
        or not isinstance(routed_collections, tuple)
        or not isinstance(proofs, tuple)
        or len(direct_candidates) > _MAXIMUM_CANDIDATES
        or len(routed_collections) > MAXIMUM_HOSTS
        or len(proofs) > MAXIMUM_HOSTS
        or not all(isinstance(item, HostKeyCandidate) for item in direct_candidates)
        or not all(
            isinstance(item, RoutedHostKeyCandidateCollection)
            for item in routed_collections
        )
        or not all(isinstance(item, TerraformApplyTrustProof) for item in proofs)
    ):
        raise StatePersistenceError(
            "Terraform apply SSH trust inputs must be typed immutable collections"
        )


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


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if (
        expected != paths
        or paths.terraform_plans.parent != paths.terraform
        or paths.ansible_trust.parent != paths.ansible
        or paths.known_hosts.parent != paths.ansible
        or paths.ansible_ssh_config.parent != paths.ansible
    ):
        raise UnsafePathError("Terraform apply SSH trust paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform apply SSH trust requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    allowed_operation = {paths.operations / f"{operation_id}.json"}
    _refuse_matching_unknown(
        paths.operations,
        operation_id,
        allowed_operation,
        "Terraform apply SSH trust operation history",
    )
    allowed_plan = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-authorization.json",
        paths.terraform_plans / f"{operation_id}.terraform-state-safeguard.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-execution.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-verification.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-inventory.json",
        terraform_apply_trust_path(paths, operation_id),
    }
    _refuse_matching_unknown(
        paths.terraform_plans,
        operation_id,
        allowed_plan,
        "Terraform apply SSH trust plan history",
    )
    allowed_backup = {paths.terraform_backups / f"{operation_id}.terraform.tfstate"}
    _refuse_matching_unknown(
        paths.terraform_backups,
        operation_id,
        allowed_backup,
        "Terraform apply SSH trust backup history",
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


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


__all__ = [
    "TERRAFORM_APPLY_TRUST_FILENAME_SUFFIX",
    "TERRAFORM_APPLY_TRUST_PROOF_SCHEMA_VERSION",
    "TERRAFORM_APPLY_TRUST_REPORT_SCHEMA_VERSION",
    "TERRAFORM_APPLY_TRUST_SCHEMA_VERSION",
    "StoredTerraformApplyTrust",
    "TerraformApplyTrust",
    "TerraformApplyTrustCompanionState",
    "TerraformApplyTrustDerivativeState",
    "TerraformApplyTrustNextStep",
    "TerraformApplyTrustProof",
    "TerraformApplyTrustProofStatus",
    "TerraformApplyTrustReport",
    "TerraformApplyTrustStage",
    "TerraformApplyTrustState",
    "TerraformApplyTrustStore",
    "establish_deploy_ssh_trust",
    "terraform_apply_trust_path",
]
