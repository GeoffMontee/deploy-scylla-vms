"""Strict, read-only TOML defaults loading for non-secret desired state."""

import os
import re
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import cast

from scylla_vms.contracts import DESIRED_CONFIG_FIELD_NAMES
from scylla_vms.errors import ConfigurationError, UnsafePathError

CONFIG_SCHEMA_VERSION = "deploy-scylla-vms.config/v2"
_MAX_CONFIG_BYTES = 1024 * 1024
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:password|passphrase|secret|token|credential|private[_-]?key)"
    r"(?:$|[_-])",
    re.IGNORECASE,
)
_PRIVATE_MATERIAL = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    """Validated native TOML values; parsing this object performs no writes."""

    values: Mapping[str, object]
    path: Path | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))


def load_config(path: Path | None) -> LoadedConfig:
    """Load an explicitly selected config, or return no defaults when absent."""

    if path is None:
        return LoadedConfig({})
    if not path.is_absolute():
        raise ConfigurationError("configuration path must be absolute")
    encoded = _read_config_bytes(path)
    if not encoded:
        raise ConfigurationError("configuration file must not be empty")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ConfigurationError("configuration file is not valid UTF-8") from error
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ConfigurationError("configuration file contains invalid TOML") from error
    _reject_secret_content(document)
    if set(document) != {"schema_version", "cluster"}:
        raise ConfigurationError(
            "configuration document must contain only schema_version and cluster"
        )
    if document["schema_version"] != CONFIG_SCHEMA_VERSION:
        raise ConfigurationError("unsupported configuration schema version")
    cluster = document["cluster"]
    if not isinstance(cluster, dict):
        raise ConfigurationError("configuration cluster value must be a table")
    values = cast(dict[str, object], cluster)
    unknown = sorted(set(values) - DESIRED_CONFIG_FIELD_NAMES)
    if unknown:
        raise ConfigurationError(
            "unknown non-secret configuration field(s): " + ", ".join(unknown)
        )
    return LoadedConfig(values, path)


def _read_config_bytes(path: Path) -> bytes:
    _reject_symlink_components(path)
    if ".." in path.parts or path.resolve(strict=False) != path:
        raise UnsafePathError("configuration path is not canonical")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise ConfigurationError(
            "explicitly requested configuration file does not exist"
        ) from error
    except OSError as error:
        raise UnsafePathError("cannot safely open configuration file") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafePathError("configuration path must be a regular file")
        if opened.st_nlink != 1:
            raise UnsafePathError("configuration file has unexpected hard links")
        if os.name == "posix":
            getuid = getattr(os, "geteuid", None)
            if getuid is not None and opened.st_uid != getuid():
                raise UnsafePathError(
                    "configuration file is not owned by the current user"
                )
            if stat.S_IMODE(opened.st_mode) & 0o022:
                raise UnsafePathError(
                    "configuration file must not be writable by group or other"
                )
        named = path.lstat()
        if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise UnsafePathError("configuration file changed during access")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_CONFIG_BYTES:
                raise ConfigurationError("configuration file exceeds the size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            path_stat = current.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise UnsafePathError("cannot inspect configuration path") from error
        if stat.S_ISLNK(path_stat.st_mode):
            raise UnsafePathError("configuration path contains a symbolic link")


def _reject_secret_content(value: object, *, key: str = "") -> None:
    if (
        key
        and _SECRET_KEY.search(key)
        and key
        not in {
            "ssh_public_key_path",
            "scylla_block_volume_key_id",
            "manager_data_volume_key_id",
            "monitoring_data_volume_key_id",
        }
    ):
        raise ConfigurationError("secret-like keys are forbidden in configuration")
    if isinstance(value, str):
        if _PRIVATE_MATERIAL.search(value):
            raise ConfigurationError(
                "private key material is forbidden in configuration"
            )
        if "${" in value:
            raise ConfigurationError("configuration interpolation is not supported")
        return
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _reject_secret_content(child_value, key=str(child_key))
    elif isinstance(value, list):
        for item in value:
            _reject_secret_content(item, key=key)
