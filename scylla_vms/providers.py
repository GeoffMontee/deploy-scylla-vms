"""Provider registry without provider-specific operation behavior."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import uuid

    from scylla_vms.desired import ClusterSpec, ProposedChange


@runtime_checkable
class ProviderCapabilities(Protocol):
    """Provider-derived facts supplied to an offline adapter."""

    @property
    def provider(self) -> str: ...


@runtime_checkable
class ProviderTerraformInput(Protocol):
    """Provider-specific input satisfying the generic persistence boundary."""

    @property
    def cluster_uuid(self) -> "uuid.UUID": ...

    @property
    def cluster_name(self) -> str: ...

    @property
    def provider(self) -> str: ...

    @property
    def schema_version(self) -> str: ...

    def to_object(self) -> dict[str, object]: ...

    def digest(self) -> str: ...


@runtime_checkable
class ProviderAdapter(Protocol):
    """Provider-neutral contract for deterministic Terraform input creation."""

    @property
    def name(self) -> str: ...

    def build_terraform_input(
        self,
        spec: "ClusterSpec",
        capabilities: ProviderCapabilities,
        *,
        public_ssh_key: str,
        change_intent: tuple["ProposedChange", ...] = (),
    ) -> ProviderTerraformInput: ...


@dataclass(frozen=True, slots=True)
class ProviderDefinition:
    """One accepted cloud provider adapter."""

    name: str
    display_name: str


PROVIDERS: tuple[ProviderDefinition, ...] = (
    ProviderDefinition(name="oci", display_name="Oracle Cloud Infrastructure"),
)


def provider_names() -> tuple[str, ...]:
    """Return accepted provider names in deterministic order."""

    return tuple(provider.name for provider in PROVIDERS)


def get_provider(name: str) -> ProviderDefinition:
    """Return a provider definition by exact normalized name."""

    for provider in PROVIDERS:
        if provider.name == name:
            return provider
    raise KeyError(name)


def get_provider_adapter(name: str) -> ProviderAdapter:
    """Return the only implemented provider adapter without unsupported stubs."""

    if name == "oci":
        from scylla_vms.oci import OCI_ADAPTER

        return OCI_ADAPTER
    raise KeyError(name)
