"""Terraform CLI machine-readable version contract."""

import json
import re
from dataclasses import dataclass
from typing import Any

from scylla_vms.errors import ToolPrerequisiteError

MINIMUM_TERRAFORM_VERSION = (1, 5, 0)
MAXIMUM_TERRAFORM_VERSION = (2, 0, 0)
MAXIMUM_VERSION_OUTPUT_BYTES = 64 * 1024
_VERSION = re.compile(
    r"(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)(?P<prerelease>-[0-9A-Za-z.-]+)?\Z"
)
_VERSION_KEYS = frozenset(
    {
        "terraform_version",
        "platform",
        "provider_selections",
        "terraform_outdated",
    }
)


class TerraformVersionError(ToolPrerequisiteError):
    """Terraform version output is malformed or outside the supported range."""


@dataclass(frozen=True, order=True, slots=True)
class TerraformVersion:
    """Validated stable Terraform semantic version."""

    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class TerraformToolchain:
    """Validated Terraform executable/version pair."""

    version: TerraformVersion


def parse_terraform_version_json(data: str | bytes) -> TerraformVersion:
    """Parse strict bounded output from ``terraform version -json``."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAXIMUM_VERSION_OUTPUT_BYTES:
        raise TerraformVersionError("Terraform version output exceeds the size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, TerraformVersionError) as error:
        raise TerraformVersionError("Terraform version output is malformed") from error
    if not isinstance(value, dict) or set(value) != _VERSION_KEYS:
        raise TerraformVersionError("Terraform version output fields are invalid")
    version_text = value["terraform_version"]
    platform = value["platform"]
    selections = value["provider_selections"]
    outdated = value["terraform_outdated"]
    if (
        not isinstance(version_text, str)
        or not isinstance(platform, str)
        or not platform
        or not isinstance(selections, dict)
        or not all(
            isinstance(name, str)
            and name
            and isinstance(version, str)
            and _VERSION.fullmatch(version)
            for name, version in selections.items()
        )
        or not isinstance(outdated, bool)
    ):
        raise TerraformVersionError("Terraform version output values are invalid")
    match = _VERSION.fullmatch(version_text)
    if match is None:
        raise TerraformVersionError("Terraform version string is invalid")
    if match.group("prerelease") is not None:
        raise TerraformVersionError("Terraform prerelease builds are unsupported")
    version = TerraformVersion(
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )
    version_tuple = (version.major, version.minor, version.patch)
    if not MINIMUM_TERRAFORM_VERSION <= version_tuple < MAXIMUM_TERRAFORM_VERSION:
        raise TerraformVersionError(
            "Terraform version is unsupported; require >=1.5.0,<2.0.0"
        )
    return version


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise TerraformVersionError("Terraform version output has duplicate keys")
        result[name] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise TerraformVersionError(f"invalid JSON constant: {value}")
