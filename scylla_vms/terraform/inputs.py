"""Strict generation-guarded Terraform variable persistence."""

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scylla_vms.errors import ConfigurationError, StatePersistenceError
from scylla_vms.oci import OciTerraformInput
from scylla_vms.persistence import (
    AtomicJsonFile,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    validate_digest,
)
from scylla_vms.providers import ProviderTerraformInput, get_provider
from scylla_vms.state import StatePaths, validate_cluster_name, validate_state_file

if TYPE_CHECKING:
    from scylla_vms.locking import ClusterLock

TERRAFORM_TFVARS_SCHEMA_VERSION = "deploy-scylla-vms.tfvars/v1"


@dataclass(frozen=True, slots=True)
class TerraformInputRecord:
    """One strict ``.tfvars.json`` generation and provider input."""

    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    captured_at: str
    input_digest: str
    terraform_input: ProviderTerraformInput
    schema_version: str = TERRAFORM_TFVARS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TERRAFORM_TFVARS_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported Terraform tfvars schema")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise StatePersistenceError("Terraform tfvars generation must be positive")
        if not isinstance(self.cluster_uuid, uuid.UUID):
            raise StatePersistenceError("Terraform tfvars cluster UUID is invalid")
        try:
            validate_cluster_name(self.cluster_name)
            get_provider(self.provider)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Terraform tfvars identity is invalid"
            ) from error
        parse_timestamp(self.captured_at)
        validate_digest(self.input_digest, "Terraform input digest")
        if (
            not isinstance(self.terraform_input, ProviderTerraformInput)
            or self.terraform_input.cluster_uuid != self.cluster_uuid
            or self.terraform_input.cluster_name != self.cluster_name
            or self.terraform_input.provider != self.provider
            or self.terraform_input.digest() != self.input_digest
        ):
            raise StatePersistenceError("Terraform input envelope is inconsistent")
        try:
            parsed = _parse_provider_input(
                self.provider, self.terraform_input.to_object()
            )
        except ConfigurationError as error:
            raise StatePersistenceError(
                "Terraform provider input is invalid"
            ) from error
        if parsed.to_object() != self.terraform_input.to_object():
            raise StatePersistenceError("Terraform provider input is not canonical")

    @classmethod
    def create(
        cls,
        terraform_input: ProviderTerraformInput,
        *,
        clock: Callable[[], datetime],
    ) -> "TerraformInputRecord":
        return cls(
            1,
            terraform_input.cluster_uuid,
            terraform_input.cluster_name,
            terraform_input.provider,
            format_timestamp(clock()),
            terraform_input.digest(),
            terraform_input,
        )

    def next_generation(
        self,
        terraform_input: ProviderTerraformInput,
        *,
        clock: Callable[[], datetime],
    ) -> "TerraformInputRecord":
        timestamp = format_timestamp(clock())
        if parse_timestamp(timestamp) < parse_timestamp(self.captured_at):
            raise StatePersistenceError("Terraform tfvars timestamp regressed")
        return TerraformInputRecord(
            self.generation + 1,
            self.cluster_uuid,
            self.cluster_name,
            self.provider,
            timestamp,
            terraform_input.digest(),
            terraform_input,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "deploy_scylla_vms_input": self.terraform_input.to_object(),
            "deploy_scylla_vms_metadata": {
                "captured_at": self.captured_at,
                "cluster_name": self.cluster_name,
                "cluster_uuid": str(self.cluster_uuid),
                "generation": self.generation,
                "input_digest": self.input_digest,
                "provider": self.provider,
                "schema_version": self.schema_version,
            },
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "TerraformInputRecord":
        require_exact_keys(
            value,
            {"deploy_scylla_vms_input", "deploy_scylla_vms_metadata"},
            "Terraform tfvars",
        )
        metadata_value = value["deploy_scylla_vms_metadata"]
        if not isinstance(metadata_value, dict):
            raise StatePersistenceError("Terraform tfvars metadata must be an object")
        metadata = cast(dict[str, object], metadata_value)
        require_exact_keys(
            metadata,
            {
                "captured_at",
                "cluster_name",
                "cluster_uuid",
                "generation",
                "input_digest",
                "provider",
                "schema_version",
            },
            "Terraform tfvars metadata",
        )
        generation = metadata["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise StatePersistenceError(
                "Terraform tfvars generation must be an integer"
            )
        provider = require_string(metadata, "provider")
        try:
            terraform_input = _parse_provider_input(
                provider, value["deploy_scylla_vms_input"]
            )
        except ConfigurationError as error:
            raise StatePersistenceError(
                "Terraform provider input is invalid"
            ) from error
        return cls(
            generation,
            parse_uuid(
                require_string(metadata, "cluster_uuid"),
                "Terraform tfvars cluster UUID",
            ),
            require_string(metadata, "cluster_name"),
            provider,
            require_string(metadata, "captured_at"),
            require_string(metadata, "input_digest"),
            terraform_input,
            require_string(metadata, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredTerraformInput:
    record: TerraformInputRecord
    digest: str


class TerraformInputStore:
    """Atomic owner-only store for the canonical generated tfvars file."""

    def __init__(
        self,
        paths: StatePaths,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._file = AtomicJsonFile(
            paths.terraform_tfvars,
            replace=replace,
            token_factory=token_factory,
        )

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_provider: str,
    ) -> StoredTerraformInput:
        value, digest = self._file.read()
        record = TerraformInputRecord.from_object(value)
        if (
            record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.provider != expected_provider
        ):
            raise StatePersistenceError("persisted Terraform input identity conflicts")
        return StoredTerraformInput(record, digest)

    def write_locked(
        self,
        record: TerraformInputRecord,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: "ClusterLock",
    ) -> StoredTerraformInput:
        lock.assert_held_for(self._paths)
        validate_state_file(self._paths.terraform_tfvars, allow_missing=True)
        exists = self._paths.terraform_tfvars.exists()
        if not exists:
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial Terraform input write requires generation one"
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
                raise StatePersistenceError("Terraform input changed concurrently")
            if record.generation != current.record.generation + 1:
                raise StatePersistenceError(
                    "Terraform input generation must increase by exactly one"
                )
            if parse_timestamp(record.captured_at) < parse_timestamp(
                current.record.captured_at
            ):
                raise StatePersistenceError("Terraform input timestamp regressed")
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredTerraformInput(record, digest)


def _parse_provider_input(provider: str, value: object) -> ProviderTerraformInput:
    if provider == "oci":
        return OciTerraformInput.from_object(value)
    raise ConfigurationError("unsupported Terraform input provider")
