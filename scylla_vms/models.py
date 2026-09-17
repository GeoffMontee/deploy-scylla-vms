"""Immutable models at the CLI and configuration boundary."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scylla_vms.operations import OperationDefinition
from scylla_vms.providers import ProviderDefinition
from scylla_vms.secrets import SecretInputs
from scylla_vms.state import StatePaths


class DeferredValue(StrEnum):
    """A value that can only be supplied by a later lifecycle boundary."""

    PERSISTED = "persisted"
    DERIVED = "derived"


class ValueSource(StrEnum):
    """Provenance for one resolved non-secret option."""

    CLI = "cli"
    ENVIRONMENT = "environment"
    CONFIG = "config"
    DEFAULT = "default"
    PERSISTED = "persisted"
    DERIVED = "derived"
    UNSET = "unset"


ScalarValue = str | int | float | bool | Path | DeferredValue | None
OptionValue = ScalarValue | tuple[str, ...] | tuple[tuple[str, ScalarValue], ...]


@dataclass(frozen=True, slots=True)
class ResolvedOption:
    """One validated option with explicit value provenance."""

    name: str
    value: OptionValue
    source: ValueSource


@dataclass(frozen=True, slots=True)
class OperationRequest:
    """Validated, immutable operation request."""

    operation: OperationDefinition
    provider: ProviderDefinition
    cluster_name: str
    state_root: Path
    paths: StatePaths
    options: tuple[ResolvedOption, ...]
    secrets: SecretInputs

    @property
    def has_sensitive_output(self) -> bool:
        """Whether this read-only request explicitly discloses exact addresses."""

        try:
            return self.option("include_addresses").value is True
        except KeyError:
            return False

    def option(self, name: str) -> ResolvedOption:
        """Return one exact option without exposing a mutable mapping."""

        for option in self.options:
            if option.name == name:
                return option
        raise KeyError(name)
