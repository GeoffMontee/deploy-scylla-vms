"""Typed environment-only secret intake without persistence or forwarding."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from scylla_vms.errors import ConfigurationError

SECRET_ENVIRONMENT_NAMES = frozenset(
    {
        "OCI_TENANCY_OCID",
        "OCI_USER_OCID",
        "OCI_FINGERPRINT",
        "OCI_PRIVATE_KEY",
        "OCI_PRIVATE_KEY_PASSWORD",
        "OCI_RESOURCE_PRINCIPAL_VERSION",
        "OCI_RESOURCE_PRINCIPAL_RPST",
        "OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM",
        "OCI_RESOURCE_PRINCIPAL_REGION",
        "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY",
        "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY_PASSPHRASE",
        "SSH_AUTH_SOCK",
        "DEPLOY_SCYLLA_VMS_ANSIBLE_VAULT_PASSWORD",
        "DEPLOY_SCYLLA_VMS_SCYLLA_REPOSITORY_USERNAME",
        "DEPLOY_SCYLLA_VMS_SCYLLA_REPOSITORY_PASSWORD",
        "DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN",
        "DEPLOY_SCYLLA_VMS_MONITORING_AUTH_TOKEN",
    }
)


@dataclass(frozen=True, slots=True)
class SecretValue:
    """Opaque environment value whose representation never exposes contents."""

    _value: str = field(repr=False)

    def reveal_for_process_boundary(self) -> str:
        """Return the value only for a future reviewed process boundary."""

        return self._value

    def __str__(self) -> str:
        return "[REDACTED]"

    def __repr__(self) -> str:
        return "SecretValue([REDACTED])"


@dataclass(frozen=True, slots=True)
class SecretInput:
    """One named protected environment input."""

    name: str
    value: SecretValue = field(repr=False)


@dataclass(frozen=True, slots=True)
class SecretInputs:
    """Immutable collection of present environment-only protected inputs."""

    items: tuple[SecretInput, ...] = field(repr=False)

    @classmethod
    def from_environment(cls, environ: Mapping[str, str]) -> "SecretInputs":
        items: list[SecretInput] = []
        for name in sorted(SECRET_ENVIRONMENT_NAMES):
            if name not in environ:
                continue
            value = environ[name]
            if value == "":
                raise ConfigurationError(
                    f"environment-only protected input must not be empty: {name}"
                )
            items.append(SecretInput(name, SecretValue(value)))

        names = {item.name for item in items}
        if "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY" in names and "SSH_AUTH_SOCK" in names:
            raise ConfigurationError(
                "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY and SSH_AUTH_SOCK "
                "are mutually exclusive"
            )
        if (
            "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY_PASSPHRASE" in names
            and "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY" not in names
        ):
            raise ConfigurationError(
                "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY_PASSPHRASE requires "
                "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY"
            )
        if "OCI_PRIVATE_KEY_PASSWORD" in names and "OCI_PRIVATE_KEY" not in names:
            raise ConfigurationError(
                "OCI_PRIVATE_KEY_PASSWORD requires OCI_PRIVATE_KEY"
            )
        repository_pair = {
            "DEPLOY_SCYLLA_VMS_SCYLLA_REPOSITORY_USERNAME",
            "DEPLOY_SCYLLA_VMS_SCYLLA_REPOSITORY_PASSWORD",
        }
        if names & repository_pair and not repository_pair <= names:
            raise ConfigurationError(
                "Scylla repository username and password are required together"
            )
        if "SSH_AUTH_SOCK" in names:
            socket = next(
                item.value.reveal_for_process_boundary()
                for item in items
                if item.name == "SSH_AUTH_SOCK"
            )
            if not Path(socket).is_absolute():
                raise ConfigurationError("SSH_AUTH_SOCK must be an absolute path")
        return cls(tuple(items))

    @property
    def names(self) -> tuple[str, ...]:
        """Return protected input names without values."""

        return tuple(item.name for item in self.items)

    def validate_oci_auth_mode(self, mode: str, region: str | None) -> None:
        """Validate exact environment-only inputs for one OCI auth mode."""

        names = set(self.names)
        api_key = {
            "OCI_TENANCY_OCID",
            "OCI_USER_OCID",
            "OCI_FINGERPRINT",
            "OCI_PRIVATE_KEY",
        }
        resource_principal = {
            "OCI_RESOURCE_PRINCIPAL_VERSION",
            "OCI_RESOURCE_PRINCIPAL_RPST",
            "OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM",
            "OCI_RESOURCE_PRINCIPAL_REGION",
        }
        if mode == "api-key":
            missing = sorted(api_key - names)
            if missing:
                raise ConfigurationError(
                    "api-key authentication is missing protected input(s): "
                    + ", ".join(missing)
                )
            forbidden = sorted(resource_principal & names)
        elif mode == "instance-principal":
            forbidden = sorted(
                (api_key | resource_principal | {"OCI_PRIVATE_KEY_PASSWORD"}) & names
            )
        elif mode == "resource-principal":
            missing = sorted(resource_principal - names)
            if missing:
                raise ConfigurationError(
                    "resource-principal authentication is missing protected input(s): "
                    + ", ".join(missing)
                )
            forbidden = sorted((api_key | {"OCI_PRIVATE_KEY_PASSWORD"}) & names)
            resource_region = self._reveal("OCI_RESOURCE_PRINCIPAL_REGION")
            if region is not None and resource_region != region:
                raise ConfigurationError(
                    "OCI_RESOURCE_PRINCIPAL_REGION does not match --oci-region"
                )
        else:
            raise ConfigurationError("unsupported OCI authentication mode")
        if forbidden:
            raise ConfigurationError(
                f"{mode} authentication forbids protected input(s): "
                + ", ".join(forbidden)
            )

    def _reveal(self, name: str) -> str:
        for item in self.items:
            if item.name == name:
                return item.value.reveal_for_process_boundary()
        raise KeyError(name)
