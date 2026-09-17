"""Strict ScyllaDB 2026.2 package-install intent and result evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.resources
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

SCYLLA_INSTALL_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-install/v1"
SCYLLA_RELEASE_LINE = "2026.2"
SCYLLA_PACKAGE_VERSION = "2026.2.7-0.20260902.94dae629230b-1"
SCYLLA_EDITION = "enterprise"
SCYLLA_CHANNEL = "stable"
SCYLLA_ROLE_COMMIT = "42592128ff0399be8ffa18dbc985c4b026e7abd0"
SCYLLA_REPOSITORY_URI = (
    "https://downloads.scylladb.com/downloads/scylla/deb/debian-ubuntu/scylladb-2026.2"
)
SCYLLA_REPOSITORY_DEFINITION_DIGEST = (
    "sha256:bc1cf67fc0790a31142b94a977adbc751d47c4ff381a19d38f8f18e13668cd4d"
)
SCYLLA_SIGNING_KEY_URL = (
    "https://keyserver.ubuntu.com/pks/lookup?"
    "op=get&search=0x6C6ECC84F42AF147BD2A65AEC503C686B007F39E"
)
SCYLLA_SIGNING_KEY_RESOURCE = (
    "content/playbooks/roles/scylla_install/files/scylladb-2026.asc"
)
SCYLLA_SIGNING_KEY_FINGERPRINT = "6C6ECC84F42AF147BD2A65AEC503C686B007F39E"
SCYLLA_SIGNING_SUBKEY_FINGERPRINT = "EBE8C9A0BA8865F8CCA4CD4DB99CC295DFCEA1A8"
SCYLLA_SIGNING_KEY_UID = "ScyllaDB Package Signing Key 2026 <security@scylladb.com>"
SCYLLA_SIGNING_KEY_DIGEST = (
    "sha256:f2f1f4368a71820ea1f5e4e8900e59ddeec1e78cf98450f3ac84826c828ea417"
)
SCYLLA_PACKAGES = (
    "scylla",
    "scylla-conf",
    "scylla-cqlsh",
    "scylla-kernel-conf",
    "scylla-node-exporter",
    "scylla-python3",
    "scylla-server",
)

_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(r"DSV_SCYLLA_INSTALL_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "execution-failed",
        "installed-package-mismatch",
        "service-active",
        "service-unmasked",
    }
)


class ScyllaInstallStatus(StrEnum):
    INSTALLED = "installed"
    NO_CHANGE = "no-change"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ScyllaInstallEvidence:
    logical_id: str
    status: ScyllaInstallStatus
    requested_edition: str
    requested_version: str
    installed_edition: str | None
    installed_version: str | None
    packages: tuple[tuple[str, str], ...]
    repository_digest: str
    signing_key_fingerprint: str
    signing_key_digest: str
    service_masked: bool | None
    service_inactive: bool | None
    configuration_performed: bool | None
    storage_mutation_performed: bool | None
    tuning_performed: bool | None
    manager_operation_performed: bool | None
    service_started: bool | None
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_INSTALL_SCHEMA_VERSION


def build_scylla_install_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    storage: StoragePostcheckEvidence,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
    package_version: str,
    cluster_spec_digest: str,
) -> dict[str, object]:
    """Build one exact install intent after all local prerequisites reconcile."""

    validate_scylla_signing_key(load_scylla_signing_key())
    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError("Scylla install requires exact Ubuntu 24.04 evidence")
    if _PACKAGE_VERSION.fullmatch(package_version) is None:
        raise AnsibleError(
            "Scylla package version must be an exact 2026.2 release package version"
        )
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError("Scylla install requires successful current base-os")
    storage_provenance = dict(storage.provenance)
    if (
        storage.logical_id != logical_id
        or not storage.readiness_for_scylla
        or storage_provenance.get("inventory_digest") != inventory.digest
        or storage_provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "Scylla install requires successful current storage postcheck"
        )
    record = inventory.record
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or observed.record.cluster_uuid != record.cluster_uuid
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla install input provenance conflicts")
    host_ids = {
        host.logical_id
        for host in record.inventory.hosts
        if host.role.value == "scylla"
    }
    if logical_id not in host_ids:
        raise StateConflictError("Scylla install target is not a Scylla stable ID")
    provenance = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "storage_postcheck_digest": _object_digest(_storage_object(storage)),
        "trust_digest": readiness.trust_digest,
    }
    return {
        "architecture": architecture,
        "channel": SCYLLA_CHANNEL,
        "cluster_uuid": str(metadata.cluster_uuid),
        "edition": SCYLLA_EDITION,
        "image_operating_system": "Ubuntu",
        "image_operating_system_version": "24.04",
        "logical_id": logical_id,
        "package_version": package_version,
        "packages": list(SCYLLA_PACKAGES),
        "provenance": provenance,
        "release_line": SCYLLA_RELEASE_LINE,
        "repository": {
            "definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
            "uri": SCYLLA_REPOSITORY_URI,
        },
        "schema_version": SCYLLA_INSTALL_SCHEMA_VERSION,
        "signing_key": {
            "artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
            "fingerprint": SCYLLA_SIGNING_KEY_FINGERPRINT,
            "resource": SCYLLA_SIGNING_KEY_RESOURCE,
        },
        "upstream_role_commit": SCYLLA_ROLE_COMMIT,
    }


def parse_scylla_install_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ScyllaInstallEvidence:
    """Parse only the bounded normalized result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible Scylla install output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_INSTALL_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Scylla install marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError("Ansible Scylla install marker is malformed") from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Scylla install evidence is malformed")
        values.append(value)
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible Scylla install output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Scylla install recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible Scylla install recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible Scylla install evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible Scylla install evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is ScyllaInstallStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible Scylla install exit status conflicts")
    changed = evidence.status is ScyllaInstallStatus.INSTALLED
    if bool(rows[logical_id][0]) != changed:
        raise AnsibleError("Ansible Scylla install changed status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaInstallEvidence:
    expected_fields = {
        "blockers",
        "configuration_performed",
        "installed_edition",
        "installed_version",
        "logical_id",
        "manager_operation_performed",
        "packages",
        "provenance",
        "repository_digest",
        "requested_edition",
        "requested_version",
        "schema_version",
        "service_inactive",
        "service_masked",
        "service_started",
        "signing_key_digest",
        "signing_key_fingerprint",
        "status",
        "storage_mutation_performed",
        "tuning_performed",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != SCYLLA_INSTALL_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Scylla install evidence schema is invalid")
    logical_id = _text(value["logical_id"])
    requested_edition = _text(value["requested_edition"])
    requested_version = _text(value["requested_version"])
    if (
        logical_id != expected["logical_id"]
        or requested_edition != expected["edition"]
        or requested_version != expected["package_version"]
    ):
        raise AnsibleError("Ansible Scylla install evidence conflicts")
    try:
        status = ScyllaInstallStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible Scylla install status is invalid") from error
    packages_value = value["packages"]
    if not isinstance(packages_value, dict):
        raise AnsibleError("Ansible Scylla install packages are invalid")
    packages = tuple(
        sorted(
            (_text(name), _text(version)) for name, version in packages_value.items()
        )
    )
    blockers = _sorted_strings(value["blockers"])
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible Scylla install blocker is unknown")
    provenance_value = value["provenance"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible Scylla install provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    installed_edition = _optional_text(value["installed_edition"])
    installed_version = _optional_text(value["installed_version"])
    service_masked = _optional_bool(value["service_masked"])
    service_inactive = _optional_bool(value["service_inactive"])
    configuration_performed = _optional_bool(value["configuration_performed"])
    storage_mutation_performed = _optional_bool(value["storage_mutation_performed"])
    tuning_performed = _optional_bool(value["tuning_performed"])
    manager_operation_performed = _optional_bool(value["manager_operation_performed"])
    service_started = _optional_bool(value["service_started"])
    repository = cast(dict[str, object], expected["repository"])
    signing_key = cast(dict[str, object], expected["signing_key"])
    repository_digest = _require_digest(value["repository_digest"])
    key_digest = _require_digest(value["signing_key_digest"])
    key_fingerprint = _text(value["signing_key_fingerprint"])
    if (
        repository_digest != repository["definition_digest"]
        or key_digest != signing_key["artifact_digest"]
        or key_fingerprint != signing_key["fingerprint"]
    ):
        raise AnsibleError("Ansible Scylla install repository provenance conflicts")
    success = status in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
    expected_packages = tuple(
        (name, requested_version) for name in cast(list[str], expected["packages"])
    )
    if success and (
        installed_edition != requested_edition
        or installed_version != requested_version
        or packages != expected_packages
        or service_masked is not True
        or service_inactive is not True
        or configuration_performed is not False
        or storage_mutation_performed is not False
        or tuning_performed is not False
        or manager_operation_performed is not False
        or service_started is not False
        or blockers
    ):
        raise AnsibleError("Ansible Scylla install success evidence conflicts")
    if status is ScyllaInstallStatus.NOT_PREDICTED and (
        installed_edition is not None
        or installed_version is not None
        or packages
        or service_masked is not None
        or service_inactive is not None
        or configuration_performed is not None
        or storage_mutation_performed is not None
        or tuning_performed is not None
        or manager_operation_performed is not None
        or service_started is not None
        or blockers
    ):
        raise AnsibleError("Ansible Scylla install check evidence conflicts")
    if status is ScyllaInstallStatus.FAILED and (
        installed_edition is not None
        or installed_version is not None
        or packages
        or service_masked is not None
        or service_inactive is not None
        or configuration_performed is not None
        or storage_mutation_performed is not None
        or tuning_performed is not None
        or manager_operation_performed is not None
        or service_started is not None
        or not blockers
    ):
        raise AnsibleError("Ansible Scylla install failure evidence conflicts")
    return ScyllaInstallEvidence(
        logical_id,
        status,
        requested_edition,
        requested_version,
        installed_edition,
        installed_version,
        packages,
        repository_digest,
        key_fingerprint,
        key_digest,
        service_masked,
        service_inactive,
        configuration_performed,
        storage_mutation_performed,
        tuning_performed,
        manager_operation_performed,
        service_started,
        provenance,
        blockers,
    )


def _failed_evidence(expected: dict[str, object]) -> ScyllaInstallEvidence:
    repository = cast(dict[str, object], expected["repository"])
    signing_key = cast(dict[str, object], expected["signing_key"])
    provenance = cast(dict[str, object], expected["provenance"])
    return ScyllaInstallEvidence(
        _text(expected["logical_id"]),
        ScyllaInstallStatus.FAILED,
        _text(expected["edition"]),
        _text(expected["package_version"]),
        None,
        None,
        (),
        _require_digest(repository["definition_digest"]),
        _text(signing_key["fingerprint"]),
        _require_digest(signing_key["artifact_digest"]),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        tuple(sorted((_text(k), _require_digest(v)) for k, v in provenance.items())),
        ("execution-failed",),
    )


def load_scylla_signing_key() -> bytes:
    """Load the vendored public key from the packaged Ansible source."""

    resource = importlib.resources.files("scylla_vms.ansible")
    for part in SCYLLA_SIGNING_KEY_RESOURCE.split("/"):
        resource = resource.joinpath(part)
    return resource.read_bytes()


def validate_scylla_signing_key(data: bytes) -> None:
    """Require the exact authenticated public-key artifact and identity."""

    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if digest != SCYLLA_SIGNING_KEY_DIGEST:
        raise AnsibleError("packaged Scylla signing key digest conflicts")
    try:
        text = data.decode("ascii")
        body = _decode_openpgp_armor(text)
        packets = tuple(_openpgp_packets(body))
    except (UnicodeError, ValueError, binascii.Error) as error:
        raise AnsibleError("packaged Scylla signing key is malformed") from error
    primary = [value for tag, value in packets if tag == 6]
    subkeys = [value for tag, value in packets if tag == 14]
    uids = [value.decode("utf-8") for tag, value in packets if tag == 13]
    revoked = any(
        tag == 2 and len(value) >= 2 and value[1] in {0x20, 0x28, 0x30}
        for tag, value in packets
    )
    if (
        len(primary) != 1
        or len(subkeys) != 1
        or uids != [SCYLLA_SIGNING_KEY_UID]
        or revoked
        or _openpgp_v4_fingerprint(primary[0]) != SCYLLA_SIGNING_KEY_FINGERPRINT
        or _openpgp_v4_fingerprint(subkeys[0]) != SCYLLA_SIGNING_SUBKEY_FINGERPRINT
    ):
        raise AnsibleError("packaged Scylla signing key identity conflicts")


def _decode_openpgp_armor(text: str) -> bytes:
    lines = text.splitlines()
    begin = lines.index("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    end = lines.index("-----END PGP PUBLIC KEY BLOCK-----")
    encoded: list[str] = []
    in_body = False
    for line in lines[begin + 1 : end]:
        if not in_body:
            in_body = not line
            continue
        if line.startswith("="):
            break
        encoded.append(line)
    if not encoded:
        raise ValueError("empty OpenPGP armor")
    return base64.b64decode("".join(encoded), validate=True)


def _openpgp_packets(data: bytes) -> list[tuple[int, bytes]]:
    packets: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        header = data[offset]
        offset += 1
        if not header & 0x80:
            raise ValueError("invalid OpenPGP packet header")
        if header & 0x40:
            tag = header & 0x3F
            first = data[offset]
            offset += 1
            if first < 192:
                length = first
            elif first < 224:
                length = (first - 192) * 256 + data[offset] + 192
                offset += 1
            elif first == 255:
                length = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
            else:
                raise ValueError("partial OpenPGP packet length")
        else:
            tag = (header >> 2) & 0x0F
            length_type = header & 0x03
            if length_type == 3:
                length = len(data) - offset
            else:
                length_bytes = (1, 2, 4)[length_type]
                length = int.from_bytes(data[offset : offset + length_bytes], "big")
                offset += length_bytes
        end = offset + length
        if end > len(data):
            raise ValueError("truncated OpenPGP packet")
        packets.append((tag, data[offset:end]))
        offset = end
    return packets


def _openpgp_v4_fingerprint(packet: bytes) -> str:
    if not packet or packet[0] != 4 or len(packet) > 0xFFFF:
        raise ValueError("unsupported OpenPGP public key")
    framed = b"\x99" + len(packet).to_bytes(2, "big") + packet
    return hashlib.sha1(framed, usedforsecurity=False).hexdigest().upper()


def _base_os_object(value: BaseOsEvidence) -> dict[str, object]:
    return {
        "hosts": [
            {
                "changed": host.changed,
                "logical_id": host.logical_id,
                "reason": host.reason,
                "reboot_required": host.reboot_required,
                "status": host.status.value,
            }
            for host in value.hosts
        ],
        "status": value.status.value,
    }


def _storage_object(value: StoragePostcheckEvidence) -> dict[str, object]:
    return {
        "backend": value.backend,
        "blockers": list(value.blockers),
        "checks": [(item.name, item.status.value) for item in value.checks],
        "devices": list(value.devices),
        "layout": value.layout,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "readiness_for_scylla": value.readiness_for_scylla,
    }


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible Scylla install evidence has duplicate fields")
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Scylla install value is invalid")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _optional_bool(value: object) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise AnsibleError("Ansible Scylla install boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Scylla install digest is invalid")
    return text


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible Scylla install blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible Scylla install blockers are not uniquely sorted")
    return items
