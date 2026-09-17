"""Strict Ansible and packaged dependency version contracts."""

import re
from dataclasses import dataclass

from scylla_vms.errors import ToolPrerequisiteError

MINIMUM_ANSIBLE_CORE_VERSION = (2, 17, 0)
MAXIMUM_ANSIBLE_CORE_VERSION = (2, 21, 0)
SUPPORTED_ANSIBLE_LINT = ">=25,<27"
SUPPORTED_YAMLLINT = ">=1.35,<2"
MAXIMUM_VERSION_OUTPUT_BYTES = 64 * 1024
PINNED_COLLECTIONS: tuple[tuple[str, str], ...] = ()
PINNED_ROLES: tuple[tuple[str, str], ...] = (
    (
        "scylladb.scylla_node",
        "42592128ff0399be8ffa18dbc985c4b026e7abd0",
    ),
)
DEPENDENCY_BLOCKER = (
    "the pinned upstream role is provenance for future Scylla configuration; "
    "scylla-install uses its constrained wrapper-owned apt implementation"
)
_CORE_LINE = re.compile(
    r"ansible-(?:playbook|inventory) \[core "
    r"(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)(?P<suffix>[^]]*)\]\r?\n?"
)


class AnsibleVersionError(ToolPrerequisiteError):
    """Ansible version output is malformed or unsupported."""


@dataclass(frozen=True, order=True, slots=True)
class AnsibleCoreVersion:
    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class AnsibleToolchain:
    core: AnsibleCoreVersion
    collections: tuple[tuple[str, str], ...] = PINNED_COLLECTIONS
    roles: tuple[tuple[str, str], ...] = PINNED_ROLES

    @property
    def production_dependencies_ready(self) -> bool:
        return bool(self.collections or self.roles)


def parse_ansible_core_version(
    data: str | bytes, *, expected_executable: str | None = None
) -> AnsibleCoreVersion:
    """Parse the first machine-stable line of ``ansible-* --version``."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAXIMUM_VERSION_OUTPUT_BYTES:
        raise AnsibleVersionError("Ansible version output exceeds the size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise AnsibleVersionError("Ansible version output is not UTF-8") from error
    first = text.splitlines(keepends=True)[0] if text else ""
    match = _CORE_LINE.fullmatch(first)
    if match is None:
        raise AnsibleVersionError("Ansible version output is malformed")
    if expected_executable is not None and not first.startswith(
        f"{expected_executable} [core "
    ):
        raise AnsibleVersionError("Ansible version output names the wrong executable")
    if match.group("suffix"):
        raise AnsibleVersionError("Ansible prerelease or vendor builds are unsupported")
    version = AnsibleCoreVersion(
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )
    value = (version.major, version.minor, version.patch)
    if not MINIMUM_ANSIBLE_CORE_VERSION <= value < MAXIMUM_ANSIBLE_CORE_VERSION:
        raise AnsibleVersionError(
            "Ansible core version is unsupported; require >=2.17.0,<2.21.0"
        )
    return version
