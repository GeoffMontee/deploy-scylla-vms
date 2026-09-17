"""Immutable, redacted checkpoints for reviewed Terraform saved plans."""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StatePersistenceError,
    TerraformError,
    UnsafePathError,
)
from scylla_vms.journal import (
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import (
    OperationClassification,
    OperationDefinition,
    get_operation,
)
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadataStore,
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
from scylla_vms.terraform.inputs import StoredTerraformInput, TerraformInputStore
from scylla_vms.terraform.source import (
    StoredTerraformSource,
    TerraformSourceStore,
    validate_staged_source,
)
from scylla_vms.terraform.toolchain import (
    MAXIMUM_TERRAFORM_VERSION,
    MINIMUM_TERRAFORM_VERSION,
    TerraformToolchain,
)

TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-plan-checkpoint/v1"
)
TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION = "deploy-scylla-vms.terraform-plan-review/v1"
TERRAFORM_PLAN_FORMAT_VERSION = "1.2"
TERRAFORM_PLAN_BACKEND_KIND = "canonical-local"

_MAXIMUM_PLAN_JSON_BYTES = 4 * 1024 * 1024
_MAXIMUM_PLAN_FILE_BYTES = 64 * 1024 * 1024
_MAXIMUM_STATE_BYTES = 64 * 1024 * 1024
_MAXIMUM_CHANGES = 10000
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_PLAN_FORMAT = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_SAFE_TEXT = re.compile(r"[\x20-\x7e]{1,1024}\Z")
_PLAN_TOP_LEVEL_KEYS = frozenset(
    {
        "applyable",
        "action_invocations",
        "checks",
        "complete",
        "configuration",
        "deferred_changes",
        "errored",
        "format_version",
        "output_changes",
        "planned_values",
        "prior_state",
        "relevant_attributes",
        "resource_changes",
        "resource_drift",
        "timestamp",
        "terraform_version",
        "variables",
    }
)
_PLAN_REQUIRED_KEYS = frozenset(
    {
        "configuration",
        "format_version",
        "output_changes",
        "planned_values",
        "prior_state",
        "resource_changes",
        "resource_drift",
        "terraform_version",
    }
)
_PRIOR_STATE_KEYS = frozenset(
    {"checks", "format_version", "terraform_version", "values"}
)
_CONFIGURATION_KEYS = frozenset({"provider_config", "root_module"})
_PLANNED_VALUES_KEYS = frozenset({"outputs", "root_module"})
_STATE_REPRESENTATION_FORMAT_VERSION = "1.0"
_RESOURCE_CHANGE_KEYS = frozenset(
    {
        "address",
        "action_reason",
        "change",
        "deposed",
        "index",
        "mode",
        "module_address",
        "name",
        "previous_address",
        "provider_name",
        "type",
    }
)
_CHANGE_KEYS = frozenset(
    {
        "actions",
        "after",
        "after_identity",
        "after_identity_unknown",
        "after_sensitive",
        "after_unknown",
        "before",
        "before_identity",
        "before_sensitive",
        "generated_config",
        "importing",
        "replace_paths",
    }
)


class TerraformPlanChangeClass(StrEnum):
    """Highest mutation class present in a saved plan."""

    NO_CHANGES = "no-changes"
    CREATE_ONLY = "create-only"
    NON_DESTRUCTIVE = "non-destructive"
    DESTRUCTIVE = "destructive"


class TerraformPlanDriftClass(StrEnum):
    """Conservative classification of refresh drift represented by a plan."""

    NONE = "none"
    REVIEW_REQUIRED = "review-required"
    CONFLICT = "conflict"


class TerraformStatePresence(StrEnum):
    """Whether a canonical local state snapshot existed when planning completed."""

    ABSENT = "absent"
    PRESENT = "present"


@dataclass(frozen=True, slots=True)
class TerraformActionCounts:
    """Bounded counts that disclose no resource address or value."""

    no_op: int = 0
    read: int = 0
    create: int = 0
    update: int = 0
    delete: int = 0
    replace: int = 0

    def __post_init__(self) -> None:
        values = (
            self.no_op,
            self.read,
            self.create,
            self.update,
            self.delete,
            self.replace,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > _MAXIMUM_CHANGES
            for value in values
        ):
            raise StatePersistenceError("Terraform plan action counts are invalid")
        if sum(values) > _MAXIMUM_CHANGES:
            raise StatePersistenceError("Terraform plan has too many changes")

    @property
    def mutation_count(self) -> int:
        return self.create + self.update + self.delete + self.replace

    @property
    def destructive_count(self) -> int:
        return self.delete + self.replace

    def to_object(self) -> dict[str, object]:
        return {
            "create": self.create,
            "delete": self.delete,
            "no_op": self.no_op,
            "read": self.read,
            "replace": self.replace,
            "update": self.update,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformActionCounts:
        require_exact_keys(
            value,
            {"create", "delete", "no_op", "read", "replace", "update"},
            "Terraform action counts",
        )
        counts: list[int] = []
        for name in ("no_op", "read", "create", "update", "delete", "replace"):
            item = value[name]
            if isinstance(item, bool) or not isinstance(item, int):
                raise StatePersistenceError("Terraform action count must be an integer")
            counts.append(item)
        return cls(*counts)


@dataclass(frozen=True, slots=True)
class TerraformStateIdentity:
    """Redacted identity of the exact canonical pre-apply state snapshot."""

    presence: TerraformStatePresence
    state_format_version: int | None
    terraform_version: str | None
    serial: int | None
    lineage_digest: str | None
    state_digest: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.presence, TerraformStatePresence):
            raise StatePersistenceError("Terraform state presence is invalid")
        if self.presence is TerraformStatePresence.ABSENT:
            if any(
                value is not None
                for value in (
                    self.state_format_version,
                    self.terraform_version,
                    self.serial,
                    self.lineage_digest,
                    self.state_digest,
                )
            ):
                raise StatePersistenceError(
                    "absent Terraform state cannot have identity fields"
                )
            return
        if (
            isinstance(self.state_format_version, bool)
            or not isinstance(self.state_format_version, int)
            or self.state_format_version < 1
            or isinstance(self.serial, bool)
            or not isinstance(self.serial, int)
            or self.serial < 0
            or not isinstance(self.terraform_version, str)
        ):
            raise StatePersistenceError("Terraform state identity is invalid")
        _validate_terraform_version(self.terraform_version)
        if self.lineage_digest is None or self.state_digest is None:
            raise StatePersistenceError("Terraform state digests are missing")
        validate_digest(self.lineage_digest, "Terraform state lineage digest")
        validate_digest(self.state_digest, "Terraform state digest")

    def to_object(self) -> dict[str, object]:
        return {
            "lineage_digest": self.lineage_digest,
            "presence": self.presence.value,
            "serial": self.serial,
            "state_digest": self.state_digest,
            "state_format_version": self.state_format_version,
            "terraform_version": self.terraform_version,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformStateIdentity:
        require_exact_keys(
            value,
            {
                "lineage_digest",
                "presence",
                "serial",
                "state_digest",
                "state_format_version",
                "terraform_version",
            },
            "Terraform state identity",
        )
        try:
            presence = TerraformStatePresence(require_string(value, "presence"))
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform state presence is invalid"
            ) from error
        optional_ints: list[int | None] = []
        for name in ("state_format_version", "serial"):
            item = value[name]
            if item is not None and (
                isinstance(item, bool) or not isinstance(item, int)
            ):
                raise StatePersistenceError(
                    "Terraform state numeric identity is invalid"
                )
            optional_ints.append(item)
        optional_strings: list[str | None] = []
        for name in ("terraform_version", "lineage_digest", "state_digest"):
            item = value[name]
            if item is not None and (not isinstance(item, str) or not item):
                raise StatePersistenceError(
                    "Terraform state string identity is invalid"
                )
            optional_strings.append(item)
        return cls(
            presence,
            optional_ints[0],
            optional_strings[0],
            optional_ints[1],
            optional_strings[1],
            optional_strings[2],
        )


@dataclass(frozen=True, slots=True)
class TerraformPlanSummary:
    """Strict address-free interpretation of ``terraform show -json``."""

    format_version: str
    terraform_version: str
    complete: bool
    applyable: bool
    change_class: TerraformPlanChangeClass
    drift_class: TerraformPlanDriftClass
    resource_changes: TerraformActionCounts
    output_changes: TerraformActionCounts
    resource_drift: TerraformActionCounts
    change_scope_digest: str
    destructive_scope_digest: str
    replacement_scope_digest: str
    deletion_scope_digest: str
    drift_scope_digest: str

    def __post_init__(self) -> None:
        _validate_plan_format(self.format_version)
        _validate_terraform_version(self.terraform_version)
        if not isinstance(self.complete, bool) or not isinstance(self.applyable, bool):
            raise StatePersistenceError("Terraform plan status is invalid")
        if not self.complete:
            raise StatePersistenceError("incomplete Terraform plans are unsupported")
        if not isinstance(
            self.change_class, TerraformPlanChangeClass
        ) or not isinstance(self.drift_class, TerraformPlanDriftClass):
            raise StatePersistenceError("Terraform plan classifications are invalid")
        if not all(
            isinstance(item, TerraformActionCounts)
            for item in (
                self.resource_changes,
                self.output_changes,
                self.resource_drift,
            )
        ):
            raise StatePersistenceError("Terraform plan counts are invalid")
        for label, value in (
            ("Terraform change scope digest", self.change_scope_digest),
            ("Terraform destructive scope digest", self.destructive_scope_digest),
            ("Terraform replacement scope digest", self.replacement_scope_digest),
            ("Terraform deletion scope digest", self.deletion_scope_digest),
            ("Terraform drift scope digest", self.drift_scope_digest),
        ):
            validate_digest(value, label)
        expected_change_class = _change_class(
            self.resource_changes, self.output_changes
        )
        expected_drift_class = _drift_class(self.resource_drift)
        if (
            self.change_class is not expected_change_class
            or self.drift_class is not expected_drift_class
        ):
            raise StatePersistenceError("Terraform plan classification conflicts")
        has_changes = (
            self.resource_changes.mutation_count > 0
            or self.output_changes.mutation_count > 0
        )
        if has_changes and not self.applyable:
            raise StatePersistenceError(
                "Terraform plan has changes but is not applyable"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "applyable": self.applyable,
            "change_class": self.change_class.value,
            "change_scope_digest": self.change_scope_digest,
            "complete": self.complete,
            "deletion_scope_digest": self.deletion_scope_digest,
            "destructive_scope_digest": self.destructive_scope_digest,
            "drift_class": self.drift_class.value,
            "drift_scope_digest": self.drift_scope_digest,
            "format_version": self.format_version,
            "output_changes": self.output_changes.to_object(),
            "resource_changes": self.resource_changes.to_object(),
            "resource_drift": self.resource_drift.to_object(),
            "replacement_scope_digest": self.replacement_scope_digest,
            "terraform_version": self.terraform_version,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformPlanSummary:
        require_exact_keys(
            value,
            {
                "applyable",
                "change_class",
                "change_scope_digest",
                "complete",
                "deletion_scope_digest",
                "destructive_scope_digest",
                "drift_class",
                "drift_scope_digest",
                "format_version",
                "output_changes",
                "resource_changes",
                "resource_drift",
                "replacement_scope_digest",
                "terraform_version",
            },
            "Terraform plan summary",
        )
        complete = value["complete"]
        applyable = value["applyable"]
        if not isinstance(complete, bool) or not isinstance(applyable, bool):
            raise StatePersistenceError("Terraform plan status must be boolean")
        resource_changes = _counts_from_value(value["resource_changes"])
        output_changes = _counts_from_value(value["output_changes"])
        resource_drift = _counts_from_value(value["resource_drift"])
        try:
            change_class = TerraformPlanChangeClass(
                require_string(value, "change_class")
            )
            drift_class = TerraformPlanDriftClass(require_string(value, "drift_class"))
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform plan classification is invalid"
            ) from error
        return cls(
            require_string(value, "format_version"),
            require_string(value, "terraform_version"),
            complete,
            applyable,
            change_class,
            drift_class,
            resource_changes,
            output_changes,
            resource_drift,
            require_string(value, "change_scope_digest"),
            require_string(value, "destructive_scope_digest"),
            require_string(value, "replacement_scope_digest"),
            require_string(value, "deletion_scope_digest"),
            require_string(value, "drift_scope_digest"),
        )


@dataclass(frozen=True, slots=True)
class TerraformPlanCheckpoint:
    """Immutable operation-scoped binding for one reviewed saved plan."""

    generation: int
    operation_id: uuid.UUID
    operation: str
    classification: OperationClassification
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    created_at: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    metadata_generation: int
    metadata_digest: str
    desired_spec_digest: str
    tfvars_generation: int
    tfvars_digest: str
    input_digest: str
    source_generation: int
    source_digest: str
    source_version: str
    source_bundle_digest: str
    backend_kind: str
    state_identity: TerraformStateIdentity
    plan_binary_digest: str
    plan_json_digest: str
    summary: TerraformPlanSummary
    checkpoint_digest: str
    schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported Terraform plan checkpoint schema")
        if self.generation != 1:
            raise StatePersistenceError(
                "Terraform plan checkpoint generation must be one"
            )
        if not isinstance(self.operation_id, uuid.UUID) or not isinstance(
            self.cluster_uuid, uuid.UUID
        ):
            raise StatePersistenceError("Terraform plan checkpoint UUID is invalid")
        try:
            operation = get_operation(self.operation)
            validate_cluster_name(self.cluster_name)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Terraform plan checkpoint identity is invalid"
            ) from error
        if (
            operation.classification is not self.classification
            or self.classification is OperationClassification.READ_ONLY
            or self.provider != "oci"
        ):
            raise StatePersistenceError(
                "Terraform plan checkpoint operation is invalid"
            )
        parse_timestamp(self.created_at)
        for generation_value in (
            self.journal_generation,
            self.metadata_generation,
            self.tfvars_generation,
            self.source_generation,
        ):
            if (
                isinstance(generation_value, bool)
                or not isinstance(generation_value, int)
                or generation_value < 1
            ):
                raise StatePersistenceError(
                    "Terraform plan binding generation is invalid"
                )
        for label, digest_value in (
            ("operation request digest", self.request_digest),
            ("operation journal digest", self.journal_digest),
            ("cluster metadata digest", self.metadata_digest),
            ("desired specification digest", self.desired_spec_digest),
            ("Terraform tfvars digest", self.tfvars_digest),
            ("Terraform input digest", self.input_digest),
            ("Terraform source record digest", self.source_digest),
            ("Terraform source bundle digest", self.source_bundle_digest),
            ("Terraform saved plan digest", self.plan_binary_digest),
            ("Terraform plan JSON digest", self.plan_json_digest),
            ("Terraform plan checkpoint digest", self.checkpoint_digest),
        ):
            validate_digest(digest_value, label)
        if (
            self.backend_kind != TERRAFORM_PLAN_BACKEND_KIND
            or not isinstance(self.state_identity, TerraformStateIdentity)
            or not isinstance(self.summary, TerraformPlanSummary)
            or not self.source_version
            or not _SAFE_TEXT.fullmatch(self.source_version)
        ):
            raise StatePersistenceError("Terraform plan checkpoint binding is invalid")
        if self.checkpoint_digest != _checkpoint_digest(self):
            raise StatePersistenceError(
                "Terraform plan checkpoint digest does not match"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "backend_kind": self.backend_kind,
            "checkpoint_digest": self.checkpoint_digest,
            "classification": self.classification.value,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "created_at": self.created_at,
            "desired_spec_digest": self.desired_spec_digest,
            "generation": self.generation,
            "input_digest": self.input_digest,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "metadata_digest": self.metadata_digest,
            "metadata_generation": self.metadata_generation,
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "plan_binary_digest": self.plan_binary_digest,
            "plan_json_digest": self.plan_json_digest,
            "provider": self.provider,
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "source_bundle_digest": self.source_bundle_digest,
            "source_digest": self.source_digest,
            "source_generation": self.source_generation,
            "source_version": self.source_version,
            "state_identity": self.state_identity.to_object(),
            "summary": self.summary.to_object(),
            "tfvars_digest": self.tfvars_digest,
            "tfvars_generation": self.tfvars_generation,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformPlanCheckpoint:
        require_exact_keys(value, set(_CHECKPOINT_KEYS), "Terraform plan checkpoint")
        generation_fields: list[int] = []
        for name in (
            "generation",
            "journal_generation",
            "metadata_generation",
            "tfvars_generation",
            "source_generation",
        ):
            item = value[name]
            if isinstance(item, bool) or not isinstance(item, int):
                raise StatePersistenceError(
                    "Terraform plan binding generation must be an integer"
                )
            generation_fields.append(item)
        try:
            classification = OperationClassification(
                require_string(value, "classification")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform plan classification is invalid"
            ) from error
        state_value = value["state_identity"]
        summary_value = value["summary"]
        if not isinstance(state_value, dict) or not isinstance(summary_value, dict):
            raise StatePersistenceError(
                "Terraform plan state or summary must be an object"
            )
        return cls(
            generation_fields[0],
            parse_uuid(require_string(value, "operation_id"), "operation ID"),
            require_string(value, "operation"),
            classification,
            parse_uuid(require_string(value, "cluster_uuid"), "cluster UUID"),
            require_string(value, "cluster_name"),
            require_string(value, "provider"),
            require_string(value, "created_at"),
            require_string(value, "request_digest"),
            generation_fields[1],
            require_string(value, "journal_digest"),
            generation_fields[2],
            require_string(value, "metadata_digest"),
            require_string(value, "desired_spec_digest"),
            generation_fields[3],
            require_string(value, "tfvars_digest"),
            require_string(value, "input_digest"),
            generation_fields[4],
            require_string(value, "source_digest"),
            require_string(value, "source_version"),
            require_string(value, "source_bundle_digest"),
            require_string(value, "backend_kind"),
            TerraformStateIdentity.from_object(cast(dict[str, object], state_value)),
            require_string(value, "plan_binary_digest"),
            require_string(value, "plan_json_digest"),
            TerraformPlanSummary.from_object(cast(dict[str, object], summary_value)),
            require_string(value, "checkpoint_digest"),
            require_string(value, "schema_version"),
        )


_CHECKPOINT_KEYS = frozenset(
    {
        "backend_kind",
        "checkpoint_digest",
        "classification",
        "cluster_name",
        "cluster_uuid",
        "created_at",
        "desired_spec_digest",
        "generation",
        "input_digest",
        "journal_digest",
        "journal_generation",
        "metadata_digest",
        "metadata_generation",
        "operation",
        "operation_id",
        "plan_binary_digest",
        "plan_json_digest",
        "provider",
        "request_digest",
        "schema_version",
        "source_bundle_digest",
        "source_digest",
        "source_generation",
        "source_version",
        "state_identity",
        "summary",
        "tfvars_digest",
        "tfvars_generation",
    }
)


@dataclass(frozen=True, slots=True)
class StoredTerraformPlanCheckpoint:
    record: TerraformPlanCheckpoint
    digest: str


@dataclass(frozen=True, slots=True)
class TerraformPlanReviewReport:
    """Independently versioned redacted projection for operator review."""

    operation_id: uuid.UUID
    operation: str
    classification: OperationClassification
    artifact_generation: int
    artifact_digest: str
    checkpoint_digest: str
    summary: TerraformPlanSummary
    state_identity: TerraformStateIdentity
    journal_generation: int
    journal_digest: str
    metadata_generation: int
    metadata_digest: str
    tfvars_generation: int
    tfvars_digest: str
    source_generation: int
    source_digest: str
    apply_authorization: str = "not-collected"
    apply_execution: str = "unavailable"
    schema_version: str = TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported Terraform plan review schema")
        if not isinstance(self.operation_id, uuid.UUID):
            raise StatePersistenceError("Terraform plan review operation ID is invalid")
        try:
            operation = get_operation(self.operation)
        except KeyError as error:
            raise StatePersistenceError(
                "Terraform plan review operation is invalid"
            ) from error
        if (
            operation.classification is not self.classification
            or self.classification is OperationClassification.READ_ONLY
            or self.artifact_generation != 1
            or not isinstance(self.summary, TerraformPlanSummary)
            or not isinstance(self.state_identity, TerraformStateIdentity)
        ):
            raise StatePersistenceError("Terraform plan review binding is invalid")
        for generation in (
            self.journal_generation,
            self.metadata_generation,
            self.tfvars_generation,
            self.source_generation,
        ):
            if (
                isinstance(generation, bool)
                or not isinstance(generation, int)
                or (generation < 1)
            ):
                raise StatePersistenceError(
                    "Terraform plan review generation is invalid"
                )
        if self.apply_authorization != "not-collected" or self.apply_execution != (
            "unavailable"
        ):
            raise StatePersistenceError("Terraform plan review state is invalid")
        for label, value in (
            ("Terraform plan artifact digest", self.artifact_digest),
            ("Terraform plan checkpoint digest", self.checkpoint_digest),
            ("operation journal digest", self.journal_digest),
            ("cluster metadata digest", self.metadata_digest),
            ("Terraform tfvars digest", self.tfvars_digest),
            ("Terraform source digest", self.source_digest),
        ):
            validate_digest(value, label)

    def to_object(self) -> dict[str, object]:
        return {
            "apply_authorization": self.apply_authorization,
            "apply_command_available": False,
            "apply_execution": self.apply_execution,
            "artifact": {
                "checkpoint_digest": self.checkpoint_digest,
                "digest": self.artifact_digest,
                "generation": self.artifact_generation,
            },
            "bindings": {
                "journal": {
                    "digest": self.journal_digest,
                    "generation": self.journal_generation,
                },
                "metadata": {
                    "digest": self.metadata_digest,
                    "generation": self.metadata_generation,
                },
                "source": {
                    "digest": self.source_digest,
                    "generation": self.source_generation,
                },
                "tfvars": {
                    "digest": self.tfvars_digest,
                    "generation": self.tfvars_generation,
                },
            },
            "classification": self.classification.value,
            "drift": {
                "class": self.summary.drift_class.value,
                "counts": self.summary.resource_drift.to_object(),
                "scope_digest": self.summary.drift_scope_digest,
            },
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "plan": {
                "applyable": self.summary.applyable,
                "change_class": self.summary.change_class.value,
                "change_scope_digest": self.summary.change_scope_digest,
                "complete": self.summary.complete,
                "deletion_scope_digest": self.summary.deletion_scope_digest,
                "destructive_scope_digest": self.summary.destructive_scope_digest,
                "format_version": self.summary.format_version,
                "output_counts": self.summary.output_changes.to_object(),
                "resource_counts": self.summary.resource_changes.to_object(),
                "replacement_scope_digest": self.summary.replacement_scope_digest,
                "terraform_version": self.summary.terraform_version,
            },
            "schema_version": self.schema_version,
            "state": self.state_identity.to_object(),
        }


class TerraformPlanCheckpointStore:
    """Immutable operation-scoped saved-plan metadata below ``terraform/plans``."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._operation_id = operation_id
        self._path = _plan_checkpoint_path(paths, operation_id)
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
        expected_operation: str,
    ) -> StoredTerraformPlanCheckpoint:
        value, digest = self._file.read()
        record = TerraformPlanCheckpoint.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != expected_operation
        ):
            raise StatePersistenceError("Terraform plan checkpoint identity conflicts")
        return StoredTerraformPlanCheckpoint(record, digest)

    def write_locked(
        self,
        record: TerraformPlanCheckpoint,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredTerraformPlanCheckpoint:
        lock.assert_held_for_operation(self._paths, record.operation)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("Terraform plan checkpoint ID conflicts")
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if (
            self._path.exists()
            or expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Terraform plan checkpoint requires absent generation one"
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredTerraformPlanCheckpoint(record, digest)


class TerraformPlanCheckpointService:
    """Capture and revalidate saved-plan bindings without executing Terraform."""

    def __init__(self, paths: StatePaths) -> None:
        expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
        if expected != paths:
            raise UnsafePathError(
                "Terraform plan paths do not match the canonical layout"
            )
        self._paths = paths

    def capture_locked(
        self,
        *,
        operation_id: uuid.UUID,
        operation: str,
        toolchain: TerraformToolchain,
        plan_json: str | bytes,
        clock: Callable[[], datetime],
        lock: ClusterLock,
    ) -> TerraformPlanReviewReport:
        """Persist one immutable checkpoint for an already-created saved plan."""

        operation_definition = _require_mutating_operation(operation)
        _validate_toolchain(toolchain)
        lock.assert_held_for_operation(self._paths, operation)
        artifacts = self._load_current_artifacts(operation_id, operation)
        if artifacts.journal.record.status is not JournalStatus.IN_PROGRESS or (
            artifacts.journal.record.phase is not OperationPhase.PLAN
        ):
            raise StateConflictError(
                "Terraform plan checkpoint requires an in-progress PLAN journal"
            )
        if artifacts.journal.record.evidence:
            raise StateConflictError(
                "Terraform plan checkpoint must precede combined PLAN evidence"
            )
        summary, plan_json_digest = parse_terraform_plan_json(plan_json)
        if summary.terraform_version != str(toolchain.version):
            raise StateConflictError("Terraform saved-plan toolchain version conflicts")
        state_identity = capture_terraform_state_identity(self._paths)
        plan_binary_digest = _digest_saved_plan(
            _saved_plan_path(self._paths, operation_id)
        )
        timestamp = format_timestamp(clock())
        record = _create_checkpoint(
            operation_id=operation_id,
            operation=operation,
            classification=operation_definition.classification,
            cluster_uuid=artifacts.metadata.record.cluster_uuid,
            cluster_name=artifacts.metadata.record.cluster_name,
            provider=artifacts.metadata.record.provider,
            created_at=timestamp,
            request_digest=artifacts.journal.record.request_digest,
            journal_generation=artifacts.journal.record.generation,
            journal_digest=artifacts.journal.digest,
            metadata_generation=artifacts.metadata.record.generation,
            metadata_digest=artifacts.metadata.digest,
            desired_spec_digest=artifacts.metadata.record.desired_spec.digest(),
            tfvars_generation=artifacts.tfvars.record.generation,
            tfvars_digest=artifacts.tfvars.digest,
            input_digest=artifacts.tfvars.record.input_digest,
            source_generation=artifacts.source.record.generation,
            source_digest=artifacts.source.digest,
            source_version=artifacts.source.record.source_version,
            source_bundle_digest=artifacts.source.record.bundle_digest,
            state_identity=state_identity,
            plan_binary_digest=plan_binary_digest,
            plan_json_digest=plan_json_digest,
            summary=summary,
        )
        stored = TerraformPlanCheckpointStore(self._paths, operation_id).write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        return _review_report(stored)

    def revalidate_locked(
        self,
        *,
        operation_id: uuid.UUID,
        operation: str,
        toolchain: TerraformToolchain,
        plan_json: str | bytes,
        lock: ClusterLock,
    ) -> TerraformPlanReviewReport:
        """Require every saved-plan and current-state binding to remain exact."""

        _validate_toolchain(toolchain)
        stored = self._revalidate_canonical_record_locked(
            operation_id=operation_id,
            operation=operation,
            lock=lock,
        )
        record = stored.record
        summary, plan_json_digest = parse_terraform_plan_json(plan_json)
        if (
            record.plan_json_digest != plan_json_digest
            or record.summary != summary
            or record.summary.terraform_version != str(toolchain.version)
        ):
            raise StateConflictError(
                "Terraform saved-plan checkpoint is stale or changed"
            )
        return _review_report(stored)

    def revalidate_canonical_locked(
        self,
        *,
        operation_id: uuid.UUID,
        operation: str,
        lock: ClusterLock,
    ) -> TerraformPlanReviewReport:
        """Revalidate every binding available from canonical persisted state."""

        return _review_report(
            self._revalidate_canonical_record_locked(
                operation_id=operation_id,
                operation=operation,
                lock=lock,
            )
        )

    def _revalidate_canonical_record_locked(
        self,
        *,
        operation_id: uuid.UUID,
        operation: str,
        lock: ClusterLock,
    ) -> StoredTerraformPlanCheckpoint:
        _require_mutating_operation(operation)
        lock.assert_held_for_operation(self._paths, operation)
        artifacts = self._load_current_artifacts(operation_id, operation)
        stored = TerraformPlanCheckpointStore(self._paths, operation_id).read(
            expected_cluster_uuid=artifacts.metadata.record.cluster_uuid,
            expected_cluster_name=artifacts.metadata.record.cluster_name,
            expected_operation=operation,
        )
        record = stored.record
        current_state = capture_terraform_state_identity(self._paths)
        current_plan_digest = _digest_saved_plan(
            _saved_plan_path(self._paths, operation_id)
        )
        if (
            record.metadata_generation != artifacts.metadata.record.generation
            or record.metadata_digest != artifacts.metadata.digest
            or record.desired_spec_digest
            != artifacts.metadata.record.desired_spec.digest()
            or record.tfvars_generation != artifacts.tfvars.record.generation
            or record.tfvars_digest != artifacts.tfvars.digest
            or record.input_digest != artifacts.tfvars.record.input_digest
            or record.source_generation != artifacts.source.record.generation
            or record.source_digest != artifacts.source.digest
            or record.source_version != artifacts.source.record.source_version
            or record.source_bundle_digest != artifacts.source.record.bundle_digest
            or record.state_identity != current_state
            or record.plan_binary_digest != current_plan_digest
        ):
            raise StateConflictError(
                "Terraform saved-plan checkpoint is stale or changed"
            )
        _validate_current_journal(
            record, artifacts.journal.record, artifacts.journal.digest
        )
        return stored

    def _load_current_artifacts(
        self, operation_id: uuid.UUID, operation: str
    ) -> _CurrentArtifacts:
        metadata = ClusterMetadataStore(self._paths).read(
            expected_cluster_name=self._paths.cluster_root.name
        )
        journal = OperationJournalStore(self._paths, operation_id).read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
        )
        if (
            journal.record.operation != operation
            or journal.record.operation_id != operation_id
            or journal.record.request_digest == ""
        ):
            raise StateConflictError("Terraform plan journal identity conflicts")
        tfvars = TerraformInputStore(self._paths).read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_provider=metadata.record.provider,
        )
        source = TerraformSourceStore(self._paths).read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
        )
        if (
            not source.record.planning_ready
            or source.record.provider != metadata.record.provider
        ):
            raise StateConflictError(
                "Terraform source is not planning-ready for this cluster"
            )
        validate_staged_source(self._paths, source)
        return _CurrentArtifacts(metadata, journal, tfvars, source)


@dataclass(frozen=True, slots=True)
class _CurrentArtifacts:
    metadata: StoredClusterMetadata
    journal: StoredOperationRecord
    tfvars: StoredTerraformInput
    source: StoredTerraformSource


def parse_terraform_plan_json(
    data: str | bytes,
) -> tuple[TerraformPlanSummary, str]:
    """Parse bounded saved-plan JSON without retaining values or addresses."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    if not isinstance(raw, bytes) or len(raw) > _MAXIMUM_PLAN_JSON_BYTES:
        raise TerraformError("Terraform plan JSON exceeds the size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_plan_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, TerraformError) as error:
        raise TerraformError("Terraform plan JSON is malformed") from error
    if not isinstance(value, dict):
        raise TerraformError("Terraform plan JSON must be an object")
    plan = cast(dict[str, object], value)
    unknown = set(plan) - _PLAN_TOP_LEVEL_KEYS
    if unknown or not set(plan) >= _PLAN_REQUIRED_KEYS:
        raise TerraformError("Terraform plan JSON fields are unsupported")
    format_version = _external_string(plan, "format_version")
    terraform_version = _external_string(plan, "terraform_version")
    try:
        _validate_plan_format(format_version)
        _validate_terraform_version(terraform_version)
    except StatePersistenceError as error:
        raise TerraformError("Terraform plan JSON version is unsupported") from error
    _validate_complete_plan_structure(plan, terraform_version)
    complete = _optional_boolean(plan, "complete", default=True)
    applyable_value = plan.get("applyable")
    errored = _optional_boolean(plan, "errored", default=False)
    deferred = plan.get("deferred_changes", [])
    action_invocations = plan.get("action_invocations", [])
    checks = plan.get("checks", [])
    if (
        errored
        or not complete
        or not isinstance(deferred, list)
        or deferred
        or not isinstance(action_invocations, list)
        or action_invocations
        or not isinstance(checks, list)
        or checks
    ):
        raise TerraformError(
            "Terraform plan is errored, incomplete, deferred, or has unmodeled checks"
        )
    resource_counts, resource_scope = _parse_resource_changes(
        plan["resource_changes"], "resource changes"
    )
    drift_counts, drift_scope = _parse_resource_changes(
        plan["resource_drift"], "resource drift"
    )
    output_counts, output_scope = _parse_output_changes(plan["output_changes"])
    has_changes = resource_counts.mutation_count > 0 or output_counts.mutation_count > 0
    if applyable_value is None:
        applyable = has_changes
    elif isinstance(applyable_value, bool):
        applyable = applyable_value
    else:
        raise TerraformError("Terraform plan applyable field must be boolean")
    try:
        summary = TerraformPlanSummary(
            format_version=format_version,
            terraform_version=terraform_version,
            complete=complete,
            applyable=applyable,
            change_class=_change_class(resource_counts, output_counts),
            drift_class=_drift_class(drift_counts),
            resource_changes=resource_counts,
            output_changes=output_counts,
            resource_drift=drift_counts,
            change_scope_digest=_scope_digest((*resource_scope, *output_scope)),
            destructive_scope_digest=_scope_digest(
                tuple(
                    item
                    for item in resource_scope
                    if item["action"] in {"delete", "replace"}
                )
            ),
            replacement_scope_digest=_scope_digest(
                tuple(item for item in resource_scope if item["action"] == "replace")
            ),
            deletion_scope_digest=_scope_digest(
                tuple(item for item in resource_scope if item["action"] == "delete")
            ),
            drift_scope_digest=_scope_digest(drift_scope),
        )
    except StatePersistenceError as error:
        raise TerraformError("Terraform plan JSON summary is invalid") from error
    return summary, digest_bytes(raw)


def _validate_complete_plan_structure(
    plan: Mapping[str, object], terraform_version: str
) -> None:
    prior_state_value = plan["prior_state"]
    configuration_value = plan["configuration"]
    planned_values_value = plan["planned_values"]
    if (
        not isinstance(prior_state_value, dict)
        or not isinstance(configuration_value, dict)
        or not isinstance(planned_values_value, dict)
    ):
        raise TerraformError(
            "Terraform plan prior state, configuration, and values must be objects"
        )
    prior_state = cast(dict[str, object], prior_state_value)
    configuration = cast(dict[str, object], configuration_value)
    planned_values = cast(dict[str, object], planned_values_value)
    if (
        set(prior_state) - _PRIOR_STATE_KEYS
        or not {"format_version", "terraform_version", "values"} <= set(prior_state)
        or set(configuration) != _CONFIGURATION_KEYS
        or set(planned_values) - _PLANNED_VALUES_KEYS
        or "root_module" not in planned_values
    ):
        raise TerraformError(
            "Terraform plan prior state, configuration, or values are incomplete"
        )
    if (
        _external_string(prior_state, "format_version")
        != _STATE_REPRESENTATION_FORMAT_VERSION
        or _external_string(prior_state, "terraform_version") != terraform_version
        or not isinstance(prior_state["values"], dict)
        or ("checks" in prior_state and not isinstance(prior_state["checks"], list))
        or not isinstance(configuration["provider_config"], dict)
        or not isinstance(configuration["root_module"], dict)
    ):
        raise TerraformError(
            "Terraform plan prior state or configuration is inconsistent"
        )
    root_module = planned_values.get("root_module")
    outputs = planned_values.get("outputs")
    if (root_module is not None and not isinstance(root_module, dict)) or (
        outputs is not None and not isinstance(outputs, dict)
    ):
        raise TerraformError("Terraform planned values structure is invalid")


def capture_terraform_state_identity(paths: StatePaths) -> TerraformStateIdentity:
    """Read only canonical local-state identity and hash the complete snapshot."""

    validate_state_file(paths.terraform_state, allow_missing=True)
    if not paths.terraform_state.exists():
        return TerraformStateIdentity(
            TerraformStatePresence.ABSENT, None, None, None, None, None
        )
    raw = _read_owner_file(
        paths.terraform_state,
        maximum_bytes=_MAXIMUM_STATE_BYTES,
        label="Terraform state",
    )
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_state_object,
            parse_constant=_reject_state_constant,
        )
    except (UnicodeDecodeError, ValueError, StatePersistenceError) as error:
        raise StatePersistenceError("Terraform state JSON is malformed") from error
    if not isinstance(value, dict):
        raise StatePersistenceError("Terraform state must be a JSON object")
    state = cast(dict[str, object], value)
    state_format = state.get("version")
    terraform_version = state.get("terraform_version")
    serial = state.get("serial")
    lineage = state.get("lineage")
    if (
        isinstance(state_format, bool)
        or not isinstance(state_format, int)
        or state_format < 1
        or not isinstance(terraform_version, str)
        or isinstance(serial, bool)
        or not isinstance(serial, int)
        or serial < 0
        or not isinstance(lineage, str)
    ):
        raise StatePersistenceError("Terraform state identity fields are invalid")
    try:
        lineage_uuid = uuid.UUID(lineage)
    except ValueError as error:
        raise StatePersistenceError("Terraform state lineage is invalid") from error
    if str(lineage_uuid) != lineage:
        raise StatePersistenceError("Terraform state lineage is not canonical")
    _validate_terraform_version(terraform_version)
    return TerraformStateIdentity(
        TerraformStatePresence.PRESENT,
        state_format,
        terraform_version,
        serial,
        digest_bytes(lineage.encode("utf-8")),
        digest_bytes(raw),
    )


def _review_report(
    stored: StoredTerraformPlanCheckpoint,
) -> TerraformPlanReviewReport:
    record = stored.record
    return TerraformPlanReviewReport(
        operation_id=record.operation_id,
        operation=record.operation,
        classification=record.classification,
        artifact_generation=record.generation,
        artifact_digest=stored.digest,
        checkpoint_digest=record.checkpoint_digest,
        summary=record.summary,
        state_identity=record.state_identity,
        journal_generation=record.journal_generation,
        journal_digest=record.journal_digest,
        metadata_generation=record.metadata_generation,
        metadata_digest=record.metadata_digest,
        tfvars_generation=record.tfvars_generation,
        tfvars_digest=record.tfvars_digest,
        source_generation=record.source_generation,
        source_digest=record.source_digest,
    )


def _create_checkpoint(
    *,
    operation_id: uuid.UUID,
    operation: str,
    classification: OperationClassification,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
    provider: str,
    created_at: str,
    request_digest: str,
    journal_generation: int,
    journal_digest: str,
    metadata_generation: int,
    metadata_digest: str,
    desired_spec_digest: str,
    tfvars_generation: int,
    tfvars_digest: str,
    input_digest: str,
    source_generation: int,
    source_digest: str,
    source_version: str,
    source_bundle_digest: str,
    state_identity: TerraformStateIdentity,
    plan_binary_digest: str,
    plan_json_digest: str,
    summary: TerraformPlanSummary,
) -> TerraformPlanCheckpoint:
    values: dict[str, object] = {
        "backend_kind": TERRAFORM_PLAN_BACKEND_KIND,
        "checkpoint_digest": "sha256:" + "0" * 64,
        "classification": classification.value,
        "cluster_name": cluster_name,
        "cluster_uuid": str(cluster_uuid),
        "created_at": created_at,
        "desired_spec_digest": desired_spec_digest,
        "generation": 1,
        "input_digest": input_digest,
        "journal_digest": journal_digest,
        "journal_generation": journal_generation,
        "metadata_digest": metadata_digest,
        "metadata_generation": metadata_generation,
        "operation": operation,
        "operation_id": str(operation_id),
        "plan_binary_digest": plan_binary_digest,
        "plan_json_digest": plan_json_digest,
        "provider": provider,
        "request_digest": request_digest,
        "schema_version": TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
        "source_bundle_digest": source_bundle_digest,
        "source_digest": source_digest,
        "source_generation": source_generation,
        "source_version": source_version,
        "state_identity": state_identity.to_object(),
        "summary": summary.to_object(),
        "tfvars_digest": tfvars_digest,
        "tfvars_generation": tfvars_generation,
    }
    values["checkpoint_digest"] = _checkpoint_digest_object(values)
    return TerraformPlanCheckpoint.from_object(values)


def _checkpoint_digest(record: TerraformPlanCheckpoint) -> str:
    return _checkpoint_digest_object(record.to_object())


def _checkpoint_digest_object(values: Mapping[str, object]) -> str:
    values = dict(values)
    values.pop("checkpoint_digest")
    return digest_bytes(serialize_json(values))


def _validate_current_journal(
    record: TerraformPlanCheckpoint, journal: OperationRecord, journal_digest: str
) -> None:
    if (
        journal.operation_id != record.operation_id
        or journal.operation != record.operation
        or journal.cluster_uuid != record.cluster_uuid
        or journal.cluster_name != record.cluster_name
        or journal.request_digest != record.request_digest
        or journal.status is not JournalStatus.IN_PROGRESS
        or journal.phase not in {OperationPhase.PLAN, OperationPhase.CONFIRM}
    ):
        raise StateConflictError("Terraform saved-plan journal binding is stale")
    if (
        journal.generation == record.journal_generation
        and journal_digest == record.journal_digest
    ):
        return
    if journal.generation <= record.journal_generation:
        raise StateConflictError("Terraform saved-plan journal generation conflicts")
    matching = tuple(
        evidence
        for evidence in journal.evidence
        if evidence.phase is OperationPhase.PLAN
        and evidence.result is EvidenceResult.VALIDATED
        and evidence.digest == record.checkpoint_digest
    )
    if len(matching) != 1:
        raise StateConflictError(
            "Terraform saved-plan journal lacks its exact PLAN checkpoint"
        )


def _require_mutating_operation(operation: str) -> OperationDefinition:
    try:
        definition = get_operation(operation)
    except KeyError as error:
        raise StatePersistenceError("Terraform plan operation is unknown") from error
    if definition.classification is OperationClassification.READ_ONLY:
        raise StatePersistenceError(
            "read-only operations cannot create Terraform saved plans"
        )
    return definition


def _validate_toolchain(toolchain: TerraformToolchain) -> None:
    if not isinstance(toolchain, TerraformToolchain):
        raise StatePersistenceError("Terraform plan toolchain is invalid")
    _validate_terraform_version(str(toolchain.version))


def _plan_checkpoint_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("Terraform plan operation ID is invalid")
    path = paths.terraform_plans / f"{operation_id}.terraform-plan.json"
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform plan checkpoint path is not canonical")
    return path


def _saved_plan_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("Terraform plan operation ID is invalid")
    path = paths.terraform_plans / f"{operation_id}.tfplan"
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform saved-plan path is not canonical")
    return path


def _digest_saved_plan(path: Path) -> str:
    raw = _read_owner_file(
        path,
        maximum_bytes=_MAXIMUM_PLAN_FILE_BYTES,
        label="Terraform saved plan",
    )
    if not raw:
        raise StatePersistenceError("Terraform saved plan is empty")
    return digest_bytes(raw)


def _read_owner_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    validate_state_file(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StatePersistenceError(f"cannot safely open {label}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise UnsafePathError(f"{label} must be a singly linked regular file")
        if os.name == "posix":
            getuid = getattr(os, "geteuid", None)
            if getuid is not None and before.st_uid != getuid():
                raise UnsafePathError(f"{label} has an unexpected owner")
            if stat.S_IMODE(before.st_mode) != 0o600:
                raise UnsafePathError(f"{label} permissions must be 0600")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise StatePersistenceError(f"{label} exceeds the size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or (
            named.st_dev,
            named.st_ino,
        ) != (after.st_dev, after.st_ino):
            raise UnsafePathError(f"{label} changed during access")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _parse_resource_changes(
    value: object, label: str
) -> tuple[TerraformActionCounts, tuple[dict[str, str], ...]]:
    if not isinstance(value, list) or len(value) > _MAXIMUM_CHANGES:
        raise TerraformError(f"Terraform {label} must be a bounded array")
    action_names: list[str] = []
    scope: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise TerraformError(f"Terraform {label} entry must be an object")
        change = cast(dict[str, object], item)
        if set(change) - _RESOURCE_CHANGE_KEYS:
            raise TerraformError(f"Terraform {label} entry fields are unsupported")
        required = {"address", "change", "mode", "name", "provider_name", "type"}
        if not required <= set(change):
            raise TerraformError(f"Terraform {label} entry fields are incomplete")
        address = _external_string(change, "address")
        mode = _external_string(change, "mode")
        resource_type = _external_string(change, "type")
        _external_string(change, "name")
        _external_string(change, "provider_name")
        if mode not in {"data", "managed"} or address in seen:
            raise TerraformError(f"Terraform {label} identity is invalid")
        seen.add(address)
        action = _parse_change_action(change["change"], label)
        action_names.append(action)
        scope.append(
            {
                "action": action,
                "address": address,
                "mode": mode,
                "type": resource_type,
            }
        )
    return _action_counts(action_names), tuple(sorted(scope, key=_scope_key))


def _parse_output_changes(
    value: object,
) -> tuple[TerraformActionCounts, tuple[dict[str, str], ...]]:
    if not isinstance(value, dict) or len(value) > _MAXIMUM_CHANGES:
        raise TerraformError("Terraform output changes must be a bounded object")
    action_names: list[str] = []
    scope: list[dict[str, str]] = []
    for name in sorted(value):
        if not isinstance(name, str) or not _SAFE_TEXT.fullmatch(name):
            raise TerraformError("Terraform output change name is invalid")
        action = _parse_change_action(value[name], "output changes")
        action_names.append(action)
        scope.append(
            {
                "action": action,
                "address": name,
                "mode": "output",
                "type": "output",
            }
        )
    return _action_counts(action_names), tuple(scope)


def _parse_change_action(value: object, label: str) -> str:
    if not isinstance(value, dict) or set(value) - _CHANGE_KEYS:
        raise TerraformError(f"Terraform {label} change fields are unsupported")
    actions = value.get("actions")
    if not isinstance(actions, list) or not all(
        isinstance(action, str) for action in actions
    ):
        raise TerraformError(f"Terraform {label} actions are invalid")
    action_tuple = tuple(actions)
    mapping = {
        ("no-op",): "no-op",
        ("read",): "read",
        ("create",): "create",
        ("update",): "update",
        ("delete",): "delete",
        ("delete", "create"): "replace",
        ("create", "delete"): "replace",
    }
    try:
        return mapping[action_tuple]
    except KeyError as error:
        raise TerraformError(f"Terraform {label} actions are unsupported") from error


def _action_counts(actions: list[str]) -> TerraformActionCounts:
    return TerraformActionCounts(
        no_op=actions.count("no-op"),
        read=actions.count("read"),
        create=actions.count("create"),
        update=actions.count("update"),
        delete=actions.count("delete"),
        replace=actions.count("replace"),
    )


def _change_class(
    resources: TerraformActionCounts, outputs: TerraformActionCounts
) -> TerraformPlanChangeClass:
    if resources.destructive_count > 0:
        return TerraformPlanChangeClass.DESTRUCTIVE
    create = resources.create + outputs.create
    update = resources.update + outputs.update + outputs.delete
    if create == 0 and update == 0:
        return TerraformPlanChangeClass.NO_CHANGES
    if create > 0 and update == 0:
        return TerraformPlanChangeClass.CREATE_ONLY
    return TerraformPlanChangeClass.NON_DESTRUCTIVE


def _drift_class(counts: TerraformActionCounts) -> TerraformPlanDriftClass:
    if counts.destructive_count > 0:
        return TerraformPlanDriftClass.CONFLICT
    if counts.mutation_count > 0:
        return TerraformPlanDriftClass.REVIEW_REQUIRED
    return TerraformPlanDriftClass.NONE


def _scope_digest(scope: tuple[dict[str, str], ...]) -> str:
    return digest_bytes(serialize_json({"scope": list(scope)}))


def _scope_key(value: dict[str, str]) -> tuple[str, str, str, str]:
    return (value["address"], value["mode"], value["type"], value["action"])


def _counts_from_value(value: object) -> TerraformActionCounts:
    if not isinstance(value, dict):
        raise StatePersistenceError("Terraform action counts must be an object")
    return TerraformActionCounts.from_object(cast(dict[str, object], value))


def _external_string(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not _SAFE_TEXT.fullmatch(item):
        raise TerraformError(f"Terraform plan string field is invalid: {name}")
    return item


def _optional_boolean(value: Mapping[str, object], name: str, *, default: bool) -> bool:
    item = value.get(name, default)
    if not isinstance(item, bool):
        raise TerraformError(f"Terraform plan boolean field is invalid: {name}")
    return item


def _validate_terraform_version(value: str) -> None:
    match = _VERSION.fullmatch(value)
    if match is None:
        raise StatePersistenceError("Terraform version is invalid")
    version = tuple(int(item) for item in match.groups())
    if not MINIMUM_TERRAFORM_VERSION <= version < MAXIMUM_TERRAFORM_VERSION:
        raise StatePersistenceError("Terraform version is unsupported")


def _validate_plan_format(value: str) -> None:
    if _PLAN_FORMAT.fullmatch(value) is None or value != TERRAFORM_PLAN_FORMAT_VERSION:
        raise StatePersistenceError("Terraform plan format version is unsupported")


def _strict_plan_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise TerraformError("Terraform plan JSON contains duplicate fields")
        result[name] = value
    return result


def _strict_state_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise StatePersistenceError("Terraform state contains duplicate fields")
        result[name] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise TerraformError(f"invalid Terraform plan JSON constant: {value}")


def _reject_state_constant(value: str) -> Any:
    raise StatePersistenceError(f"invalid Terraform state JSON constant: {value}")
