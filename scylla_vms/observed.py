"""Strict protected persistence for locally captured Terraform observations."""

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from scylla_vms.errors import ConfigurationError, StatePersistenceError, TerraformError
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
from scylla_vms.providers import get_provider
from scylla_vms.state import StatePaths, validate_cluster_name, validate_state_file
from scylla_vms.terraform.outputs import (
    HOST_MANIFEST_SCHEMA_VERSION,
    TERRAFORM_OUTPUT_SCHEMA_VERSION,
    TerraformHostManifest,
    parse_host_manifest_object,
)

if TYPE_CHECKING:
    from pathlib import Path

    from scylla_vms.locking import ClusterLock

OBSERVED_STATE_SCHEMA_VERSION = "deploy-scylla-vms.observed/v1"


class ObservationSource(StrEnum):
    """Reviewed sources allowed to create an observed record."""

    TERRAFORM_OUTPUT_JSON = "terraform-output-json"


@dataclass(frozen=True, slots=True)
class ObservedStateRecord:
    """Identity-bound generation of a validated Terraform host manifest."""

    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    captured_at: str
    source: ObservationSource
    output_schema_version: str
    manifest_schema_version: str
    manifest_digest: str
    manifest: TerraformHostManifest
    schema_version: str = OBSERVED_STATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVED_STATE_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported observed-state schema version")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise StatePersistenceError("observed-state generation must be positive")
        if not isinstance(self.cluster_uuid, uuid.UUID):
            raise StatePersistenceError("observed cluster UUID is invalid")
        try:
            validate_cluster_name(self.cluster_name)
            get_provider(self.provider)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "observed cluster identity is invalid"
            ) from error
        if (
            not isinstance(self.source, ObservationSource)
            or self.output_schema_version != TERRAFORM_OUTPUT_SCHEMA_VERSION
            or self.manifest_schema_version != HOST_MANIFEST_SCHEMA_VERSION
            or self.manifest.cluster_uuid != self.cluster_uuid
            or self.manifest.schema_version != self.manifest_schema_version
        ):
            raise StatePersistenceError("observed manifest envelope is inconsistent")
        try:
            validated_manifest = parse_host_manifest_object(
                self.manifest.to_persistence_object(),
                expected_cluster_uuid=self.cluster_uuid,
            )
        except TerraformError as error:
            raise StatePersistenceError("observed manifest is invalid") from error
        if validated_manifest != self.manifest:
            raise StatePersistenceError("observed manifest is not canonical")
        parse_timestamp(self.captured_at)
        validate_digest(self.manifest_digest, "observed manifest digest")
        if self.manifest_digest != _manifest_digest(self.manifest):
            raise StatePersistenceError("observed manifest digest does not match")

    @classmethod
    def create(
        cls,
        *,
        cluster_uuid: uuid.UUID,
        cluster_name: str,
        provider: str,
        manifest: TerraformHostManifest,
        clock: Callable[[], datetime],
    ) -> "ObservedStateRecord":
        return cls(
            generation=1,
            cluster_uuid=cluster_uuid,
            cluster_name=cluster_name,
            provider=provider,
            captured_at=format_timestamp(clock()),
            source=ObservationSource.TERRAFORM_OUTPUT_JSON,
            output_schema_version=TERRAFORM_OUTPUT_SCHEMA_VERSION,
            manifest_schema_version=HOST_MANIFEST_SCHEMA_VERSION,
            manifest_digest=_manifest_digest(manifest),
            manifest=manifest,
        )

    def next_generation(
        self,
        *,
        manifest: TerraformHostManifest,
        clock: Callable[[], datetime],
    ) -> "ObservedStateRecord":
        captured_at = format_timestamp(clock())
        if parse_timestamp(captured_at) < parse_timestamp(self.captured_at):
            raise StatePersistenceError("observed-state timestamp must not regress")
        return ObservedStateRecord(
            generation=self.generation + 1,
            cluster_uuid=self.cluster_uuid,
            cluster_name=self.cluster_name,
            provider=self.provider,
            captured_at=captured_at,
            source=self.source,
            output_schema_version=self.output_schema_version,
            manifest_schema_version=self.manifest_schema_version,
            manifest_digest=_manifest_digest(manifest),
            manifest=manifest,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "captured_at": self.captured_at,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "generation": self.generation,
            "manifest": self.manifest.to_persistence_object(),
            "manifest_digest": self.manifest_digest,
            "manifest_schema_version": self.manifest_schema_version,
            "output_schema_version": self.output_schema_version,
            "provider": self.provider,
            "schema_version": self.schema_version,
            "source": self.source.value,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "ObservedStateRecord":
        require_exact_keys(
            value,
            {
                "captured_at",
                "cluster_name",
                "cluster_uuid",
                "generation",
                "manifest",
                "manifest_digest",
                "manifest_schema_version",
                "output_schema_version",
                "provider",
                "schema_version",
                "source",
            },
            "observed state",
        )
        generation = value["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise StatePersistenceError("observed-state generation must be an integer")
        cluster_uuid = parse_uuid(
            require_string(value, "cluster_uuid"), "observed cluster UUID"
        )
        manifest_value = value["manifest"]
        if not isinstance(manifest_value, dict):
            raise StatePersistenceError("observed manifest must be an object")
        try:
            manifest = parse_host_manifest_object(
                cast(dict[str, object], manifest_value),
                expected_cluster_uuid=cluster_uuid,
            )
            source = ObservationSource(require_string(value, "source"))
        except (TerraformError, ValueError) as error:
            raise StatePersistenceError(
                "persisted observed manifest is invalid"
            ) from error
        return cls(
            generation=generation,
            cluster_uuid=cluster_uuid,
            cluster_name=require_string(value, "cluster_name"),
            provider=require_string(value, "provider"),
            captured_at=require_string(value, "captured_at"),
            source=source,
            output_schema_version=require_string(value, "output_schema_version"),
            manifest_schema_version=require_string(value, "manifest_schema_version"),
            manifest_digest=require_string(value, "manifest_digest"),
            manifest=manifest,
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredObservedState:
    record: ObservedStateRecord
    digest: str


class ObservedStateStore:
    """Atomic generation-guarded store at ``terraform/observed.json``."""

    def __init__(
        self,
        paths: StatePaths,
        *,
        replace: Callable[["Path", "Path"], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._file = AtomicJsonFile(
            paths.terraform_observed,
            replace=replace,
            token_factory=token_factory,
        )

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_provider: str,
    ) -> StoredObservedState:
        value, digest = self._file.read()
        record = ObservedStateRecord.from_object(value)
        if (
            record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.provider != expected_provider
        ):
            raise StatePersistenceError("persisted observed identity conflicts")
        return StoredObservedState(record, digest)

    def write_locked(
        self,
        record: ObservedStateRecord,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: "ClusterLock",
    ) -> StoredObservedState:
        lock.assert_held_for(self._paths)
        validate_state_file(self._paths.terraform_observed, allow_missing=True)
        exists = self._paths.terraform_observed.exists()
        if not exists:
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial observed-state write requires generation one"
                )
        else:
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_provider=record.provider,
            )
            if (
                expected_digest is None
                or current.digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError("observed state changed concurrently")
            if record.generation != current.record.generation + 1:
                raise StatePersistenceError(
                    "observed-state generation must increase by exactly one"
                )
            if (
                record.cluster_uuid != current.record.cluster_uuid
                or record.cluster_name != current.record.cluster_name
                or record.provider != current.record.provider
                or parse_timestamp(record.captured_at)
                < parse_timestamp(current.record.captured_at)
            ):
                raise StatePersistenceError(
                    "observed-state identity or timestamp regressed"
                )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredObservedState(record, digest)


def _manifest_digest(manifest: TerraformHostManifest) -> str:
    return digest_bytes(serialize_json(manifest.to_persistence_object()))
