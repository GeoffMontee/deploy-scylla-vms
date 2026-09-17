"""Strict SSH host-key candidates, trust persistence, and route rendering."""

import base64
import binascii
import hashlib
import ipaddress
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scylla_vms.ansible.source import _atomic_text
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StatePersistenceError,
)
from scylla_vms.inventory import InventoryRecord, StoredInventoryRecord
from scylla_vms.observed import ObservedStateRecord, StoredObservedState
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

if TYPE_CHECKING:
    from scylla_vms.locking import ClusterLock

TRUST_SCHEMA_VERSION = "deploy-scylla-vms.ssh-trust/v1"
APPROVED_HOST_KEY_ALGORITHMS = (
    "ecdsa-sha2-nistp256",
    "ssh-ed25519",
)
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PROVIDER_ID = re.compile(r"ocid1\.instance\.[A-Za-z0-9._:+/-]+\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_MAXIMUM_KEY_BLOB_BYTES = 16 * 1024


class TrustConfirmation(StrEnum):
    """Auditable, non-secret ways a candidate may become trusted."""

    EXPLICIT_OPERATOR = "explicit-operator"
    EXPECTED_FINGERPRINT = "expected-fingerprint"


class TrustCaptureSource(StrEnum):
    """Allowlisted origin of untrusted host-key material."""

    DIRECT_KEYSCAN = "direct-keyscan"
    LOCAL_KNOWN_HOSTS = "local-known-hosts"
    ROUTED_JUMP_KEYSCAN = "routed-jump-keyscan"
    SUPPLIED_CANDIDATE = "supplied-candidate"


@dataclass(frozen=True, slots=True)
class HostEndpoint:
    address: str
    port: int = 22

    def __post_init__(self) -> None:
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise StatePersistenceError("SSH endpoint address is invalid") from error
        if str(parsed) != self.address:
            raise StatePersistenceError("SSH endpoint address is not canonical")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise StatePersistenceError("SSH endpoint port is invalid")

    @property
    def known_hosts_name(self) -> str:
        if self.port == 22:
            return self.address
        return f"[{self.address}]:{self.port}"


@dataclass(frozen=True, slots=True)
class HostKeyCandidate:
    logical_id: str
    provider_id: str
    endpoint: HostEndpoint
    jump_host_id: str | None
    algorithm: str
    public_key: str
    fingerprint: str
    captured_at: str
    capture_source: TrustCaptureSource

    def __post_init__(self) -> None:
        _validate_identity(self.logical_id, self.provider_id, self.jump_host_id)
        if not isinstance(self.endpoint, HostEndpoint):
            raise StatePersistenceError("SSH candidate endpoint is invalid")
        key = _validate_public_key(self.algorithm, self.public_key)
        if self.fingerprint != _fingerprint(key):
            raise StatePersistenceError("SSH candidate fingerprint conflicts")
        parse_timestamp(self.captured_at)
        if not isinstance(self.capture_source, TrustCaptureSource):
            raise StatePersistenceError("SSH candidate capture source is invalid")


@dataclass(frozen=True, slots=True)
class TrustedHostKey:
    logical_id: str
    provider_id: str
    endpoint: HostEndpoint
    jump_host_id: str | None
    algorithm: str
    public_key: str
    fingerprint: str
    captured_at: str
    capture_source: TrustCaptureSource
    confirmed_at: str
    confirmation: TrustConfirmation

    def __post_init__(self) -> None:
        HostKeyCandidate(
            self.logical_id,
            self.provider_id,
            self.endpoint,
            self.jump_host_id,
            self.algorithm,
            self.public_key,
            self.fingerprint,
            self.captured_at,
            self.capture_source,
        )
        if not isinstance(self.confirmation, TrustConfirmation):
            raise StatePersistenceError("SSH trust confirmation is invalid")
        if parse_timestamp(self.confirmed_at) < parse_timestamp(self.captured_at):
            raise StatePersistenceError("SSH trust confirmation predates capture")

    def to_object(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "captured_at": self.captured_at,
            "capture_source": self.capture_source.value,
            "confirmation": self.confirmation.value,
            "confirmed_at": self.confirmed_at,
            "endpoint": {
                "address": self.endpoint.address,
                "port": self.endpoint.port,
            },
            "fingerprint": self.fingerprint,
            "jump_host_id": self.jump_host_id,
            "logical_id": self.logical_id,
            "provider_id": self.provider_id,
            "public_key": self.public_key,
        }


def confirm_host_key_candidate(
    candidate: HostKeyCandidate,
    *,
    confirmed_at: datetime,
    explicitly_confirmed: bool = False,
    expected_fingerprint: str | None = None,
) -> TrustedHostKey:
    """Promote a candidate only through explicit or independently expected trust."""

    if expected_fingerprint is not None:
        if not _FINGERPRINT.fullmatch(expected_fingerprint):
            raise StatePersistenceError("expected SSH fingerprint is malformed")
        if expected_fingerprint != candidate.fingerprint:
            raise StateConflictError(
                "SSH candidate fingerprint conflicts with expected"
            )
        confirmation = TrustConfirmation.EXPECTED_FINGERPRINT
    elif explicitly_confirmed is True:
        confirmation = TrustConfirmation.EXPLICIT_OPERATOR
    else:
        raise StateConflictError(
            "initial SSH trust requires explicit confirmation or expected fingerprint"
        )
    return TrustedHostKey(
        candidate.logical_id,
        candidate.provider_id,
        candidate.endpoint,
        candidate.jump_host_id,
        candidate.algorithm,
        candidate.public_key,
        candidate.fingerprint,
        candidate.captured_at,
        candidate.capture_source,
        format_timestamp(confirmed_at),
        confirmation,
    )


def parse_keyscan_output(
    data: str | bytes,
    *,
    logical_id: str,
    provider_id: str,
    endpoint: HostEndpoint,
    jump_host_id: str | None,
    captured_at: datetime,
    capture_source: TrustCaptureSource = TrustCaptureSource.DIRECT_KEYSCAN,
    maximum_bytes: int = 128 * 1024,
) -> tuple[HostKeyCandidate, ...]:
    """Parse bounded ssh-keyscan-style output without trusting it."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > maximum_bytes:
        raise StatePersistenceError("SSH candidate output exceeds the size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise StatePersistenceError("SSH candidate output is not UTF-8") from error
    candidates: list[HostKeyCandidate] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3:
            raise StatePersistenceError("SSH candidate output is malformed")
        host, algorithm, public_key = fields
        if host != endpoint.known_hosts_name:
            raise StateConflictError("SSH candidate endpoint conflicts")
        key = _validate_public_key(algorithm, public_key)
        candidates.append(
            HostKeyCandidate(
                logical_id,
                provider_id,
                endpoint,
                jump_host_id,
                algorithm,
                public_key,
                _fingerprint(key),
                format_timestamp(captured_at),
                capture_source,
            )
        )
    identities = tuple((item.algorithm, item.fingerprint) for item in candidates)
    if not candidates:
        raise StatePersistenceError("SSH candidate output contains no approved key")
    if len(identities) != len(set(identities)):
        raise StateConflictError(
            "SSH candidate output contains duplicates or collisions"
        )
    return tuple(
        sorted(candidates, key=lambda item: (item.algorithm, item.fingerprint))
    )


def validate_host_public_key(algorithm: str, public_key: str) -> str:
    """Validate one approved SSH wire key and return its OpenSSH fingerprint."""

    return _fingerprint(_validate_public_key(algorithm, public_key))


@dataclass(frozen=True, slots=True)
class TrustRecord:
    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    observation_generation: int
    observation_digest: str
    inventory_generation: int
    inventory_digest: str
    captured_at: str
    confirmed_at: str
    entries_digest: str
    entries: tuple[TrustedHostKey, ...]
    schema_version: str = TRUST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TRUST_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported SSH trust schema")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
            or isinstance(self.observation_generation, bool)
            or not isinstance(self.observation_generation, int)
            or self.observation_generation < 1
            or isinstance(self.inventory_generation, bool)
            or not isinstance(self.inventory_generation, int)
            or self.inventory_generation < 1
        ):
            raise StatePersistenceError("SSH trust generations are invalid")
        if not isinstance(self.cluster_uuid, uuid.UUID):
            raise StatePersistenceError("SSH trust cluster UUID is invalid")
        try:
            validate_cluster_name(self.cluster_name)
            get_provider(self.provider)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "SSH trust cluster identity is invalid"
            ) from error
        validate_digest(self.observation_digest, "SSH trust observation digest")
        validate_digest(self.inventory_digest, "SSH trust inventory digest")
        validate_digest(self.entries_digest, "SSH trust entries digest")
        if parse_timestamp(self.confirmed_at) < parse_timestamp(self.captured_at):
            raise StatePersistenceError("SSH trust timestamps regress")
        logical_ids = tuple(entry.logical_id for entry in self.entries)
        endpoints = tuple(
            (entry.endpoint.address, entry.endpoint.port) for entry in self.entries
        )
        fingerprints = tuple(entry.fingerprint for entry in self.entries)
        if (
            logical_ids != tuple(sorted(set(logical_ids)))
            or len(set(endpoints)) != len(endpoints)
            or len(set(fingerprints)) != len(fingerprints)
        ):
            raise StateConflictError("SSH trust entries contain identity collisions")
        if self.entries_digest != _entries_digest(self.entries):
            raise StatePersistenceError("SSH trust entries digest conflicts")

    @classmethod
    def create(
        cls,
        observed: ObservedStateRecord,
        inventory: InventoryRecord,
        entries: tuple[TrustedHostKey, ...],
        *,
        generation: int,
    ) -> "TrustRecord":
        ordered = tuple(sorted(entries, key=lambda item: item.logical_id))
        _validate_bindings(observed, inventory, ordered)
        captured = min(
            (entry.captured_at for entry in ordered), default=observed.captured_at
        )
        confirmed = max(
            (entry.confirmed_at for entry in ordered), default=observed.captured_at
        )
        return cls(
            generation,
            inventory.cluster_uuid,
            inventory.cluster_name,
            inventory.provider,
            observed.generation,
            observed.manifest_digest,
            inventory.generation,
            inventory.inventory_digest,
            captured,
            confirmed,
            _entries_digest(ordered),
            ordered,
        )

    def is_fresh_for(
        self, observed: ObservedStateRecord, inventory: InventoryRecord
    ) -> bool:
        return (
            self.cluster_uuid == observed.cluster_uuid == inventory.cluster_uuid
            and self.cluster_name == observed.cluster_name == inventory.cluster_name
            and self.provider == observed.provider == inventory.provider
            and self.observation_generation == observed.generation
            and self.observation_digest == observed.manifest_digest
            and self.inventory_generation == inventory.generation
            and self.inventory_digest == inventory.inventory_digest
        )

    def to_object(self) -> dict[str, object]:
        return {
            "captured_at": self.captured_at,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "confirmed_at": self.confirmed_at,
            "entries": [entry.to_object() for entry in self.entries],
            "entries_digest": self.entries_digest,
            "generation": self.generation,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "observation_digest": self.observation_digest,
            "observation_generation": self.observation_generation,
            "provider": self.provider,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "TrustRecord":
        require_exact_keys(
            value,
            {
                "captured_at",
                "cluster_name",
                "cluster_uuid",
                "confirmed_at",
                "entries",
                "entries_digest",
                "generation",
                "inventory_digest",
                "inventory_generation",
                "observation_digest",
                "observation_generation",
                "provider",
                "schema_version",
            },
            "SSH trust record",
        )
        entries_value = value["entries"]
        if not isinstance(entries_value, list):
            raise StatePersistenceError("SSH trust entries must be an array")
        return cls(
            _positive_integer(value["generation"], "SSH trust generation"),
            parse_uuid(require_string(value, "cluster_uuid"), "SSH trust cluster UUID"),
            require_string(value, "cluster_name"),
            require_string(value, "provider"),
            _positive_integer(
                value["observation_generation"], "SSH observation generation"
            ),
            require_string(value, "observation_digest"),
            _positive_integer(
                value["inventory_generation"], "SSH inventory generation"
            ),
            require_string(value, "inventory_digest"),
            require_string(value, "captured_at"),
            require_string(value, "confirmed_at"),
            require_string(value, "entries_digest"),
            tuple(_entry_from_object(item) for item in entries_value),
            require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredTrustRecord:
    record: TrustRecord
    digest: str


class TrustStore:
    """Strict trust metadata plus deterministic OpenSSH runtime files."""

    def __init__(
        self,
        paths: StatePaths,
        *,
        replace: Callable[[Path, Path], None] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        selected_replace = replace or os.replace
        self._file = AtomicJsonFile(
            paths.ansible_trust,
            replace=selected_replace,
            token_factory=token_factory,
        )

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_provider: str,
    ) -> StoredTrustRecord:
        value, digest = self._file.read()
        record = TrustRecord.from_object(value)
        if (
            record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.provider != expected_provider
        ):
            raise StatePersistenceError("persisted SSH trust identity conflicts")
        return StoredTrustRecord(record, digest)

    def write_locked(
        self,
        record: TrustRecord,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        *,
        approved: bool,
        expected_generation: int,
        expected_digest: str | None,
        lock: "ClusterLock",
    ) -> StoredTrustRecord:
        lock.assert_held_for(self._paths)
        if not approved:
            raise StateConflictError("SSH trust persistence requires explicit approval")
        if not record.is_fresh_for(observed.record, inventory.record):
            raise StateConflictError("SSH trust record is stale")
        _validate_bindings(observed.record, inventory.record, record.entries)
        known_hosts_text = render_known_hosts(record)
        ssh_config_text = render_ssh_config(
            record, inventory.record, self._paths.known_hosts
        )
        validate_state_file(self._paths.ansible_trust, allow_missing=True)
        validate_state_file(self._paths.known_hosts, allow_missing=True)
        validate_state_file(self._paths.ansible_ssh_config, allow_missing=True)
        current: StoredTrustRecord | None = None
        if self._paths.ansible_trust.exists():
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_provider=record.provider,
            )
            if (
                expected_digest != current.digest
                or expected_generation != current.record.generation
                or record.generation != current.record.generation + 1
            ):
                raise StatePersistenceError("SSH trust changed concurrently")
            if parse_timestamp(record.confirmed_at) < parse_timestamp(
                current.record.confirmed_at
            ):
                raise StatePersistenceError("SSH trust timestamp regressed")
            old = {entry.logical_id: entry for entry in current.record.entries}
            for entry in record.entries:
                if entry.logical_id in old and old[entry.logical_id] != entry:
                    raise StateConflictError(
                        "changed SSH host key or host identity requires replacement workflow"
                    )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial SSH trust write requires generation one"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        _atomic_text(self._paths.known_hosts, known_hosts_text)
        _atomic_text(self._paths.ansible_ssh_config, ssh_config_text)
        return StoredTrustRecord(record, digest)

    def prepare_runtime_transition_locked(
        self,
        stored: StoredTrustRecord,
        inventory: StoredInventoryRecord,
        *,
        lock: "ClusterLock",
    ) -> None:
        """Remove exact current derivatives before a trust-generation advance.

        The trust metadata is the authoritative record. Removing both derived
        files first ensures that an interrupted multi-file transition leaves a
        recoverable missing-derivative prefix instead of silently mixing trust
        generations.
        """

        lock.assert_held_for(self._paths)
        current = self.read(
            expected_cluster_uuid=stored.record.cluster_uuid,
            expected_cluster_name=stored.record.cluster_name,
            expected_provider=stored.record.provider,
        )
        if current != stored:
            raise StatePersistenceError("SSH trust changed before runtime transition")
        self.validate_runtime(stored, inventory)
        for path in (self._paths.known_hosts, self._paths.ansible_ssh_config):
            validate_state_file(path)
            try:
                path.unlink()
            except OSError as error:
                raise StatePersistenceError(
                    "cannot safely prepare SSH runtime transition"
                ) from error

    def recover_runtime_locked(
        self,
        stored: StoredTrustRecord,
        inventory: StoredInventoryRecord,
        *,
        lock: "ClusterLock",
    ) -> None:
        """Recover only missing deterministic derivatives for exact trust."""

        lock.assert_held_for(self._paths)
        current = self.read(
            expected_cluster_uuid=stored.record.cluster_uuid,
            expected_cluster_name=stored.record.cluster_name,
            expected_provider=stored.record.provider,
        )
        if current != stored:
            raise StatePersistenceError("SSH trust changed before runtime recovery")
        _validate_runtime_bindings(stored.record, inventory.record)
        expected = (
            (self._paths.known_hosts, render_known_hosts(stored.record)),
            (
                self._paths.ansible_ssh_config,
                render_ssh_config(
                    stored.record, inventory.record, self._paths.known_hosts
                ),
            ),
        )
        for path, text in expected:
            validate_state_file(path, allow_missing=True)
            if path.exists():
                if path.read_text(encoding="utf-8") != text:
                    raise StateConflictError(
                        "SSH runtime derivative conflicts with trust metadata"
                    )
                continue
            _atomic_text(path, text)
        reread = self.read(
            expected_cluster_uuid=stored.record.cluster_uuid,
            expected_cluster_name=stored.record.cluster_name,
            expected_provider=stored.record.provider,
        )
        if reread != stored:
            raise StatePersistenceError("SSH trust changed during runtime recovery")
        self.validate_runtime(stored, inventory)

    def validate_runtime(
        self, stored: StoredTrustRecord, inventory: StoredInventoryRecord
    ) -> None:
        validate_state_file(self._paths.known_hosts)
        validate_state_file(self._paths.ansible_ssh_config)
        if self._paths.known_hosts.read_text(encoding="utf-8") != render_known_hosts(
            stored.record
        ):
            raise StateConflictError("known_hosts conflicts with SSH trust metadata")
        if self._paths.ansible_ssh_config.read_text(
            encoding="utf-8"
        ) != render_ssh_config(
            stored.record, inventory.record, self._paths.known_hosts
        ):
            raise StateConflictError("SSH config conflicts with trust or inventory")


def _validate_runtime_bindings(trust: TrustRecord, inventory: InventoryRecord) -> None:
    if (
        trust.cluster_uuid != inventory.cluster_uuid
        or trust.cluster_name != inventory.cluster_name
        or trust.provider != inventory.provider
    ):
        raise StateConflictError("SSH trust runtime identity conflicts")
    hosts = {host.logical_id: host for host in inventory.inventory.hosts}
    for entry in trust.entries:
        host = hosts.get(entry.logical_id)
        if host is None or (
            entry.provider_id != host.provider_id
            or entry.endpoint.address != host.ansible_host
            or entry.endpoint.port != 22
            or entry.jump_host_id != host.jump_host_id
        ):
            raise StateConflictError("SSH trust runtime host binding conflicts")


def render_known_hosts(record: TrustRecord) -> str:
    return "".join(
        f"{entry.endpoint.known_hosts_name} {entry.algorithm} {entry.public_key}\n"
        for entry in record.entries
    )


def render_ssh_config(
    record: TrustRecord, inventory: InventoryRecord, known_hosts: Path
) -> str:
    trusted = {entry.logical_id: entry for entry in record.entries}
    inventory_hosts = {host.logical_id: host for host in inventory.inventory.hosts}
    lines = [
        "Host *",
        "  BatchMode yes",
        "  CheckHostIP yes",
        "  StrictHostKeyChecking yes",
        f"  UserKnownHostsFile {_ssh_config_quote(str(known_hosts))}",
        "  GlobalKnownHostsFile /dev/null",
        "",
    ]
    for logical_id in sorted(trusted):
        entry = trusted[logical_id]
        host = inventory_hosts.get(logical_id)
        if host is None:
            raise StateConflictError("SSH trust contains an unknown inventory host")
        lines.extend(
            [
                f"Host {logical_id}",
                f"  HostName {entry.endpoint.address}",
                f"  Port {entry.endpoint.port}",
                f"  User {host.ansible_user}",
                f"  HostKeyAlias {entry.endpoint.known_hosts_name}",
            ]
        )
        if entry.jump_host_id is not None:
            if entry.jump_host_id not in trusted:
                raise StateConflictError("SSH route references an untrusted jump host")
            lines.append(f"  ProxyJump {entry.jump_host_id}")
        lines.append("")
    return "\n".join(lines)


def _validate_bindings(
    observed: ObservedStateRecord,
    inventory: InventoryRecord,
    entries: tuple[TrustedHostKey, ...],
) -> None:
    if (
        observed.cluster_uuid != inventory.cluster_uuid
        or observed.cluster_name != inventory.cluster_name
        or observed.provider != inventory.provider
        or inventory.source_manifest_generation != observed.generation
        or inventory.source_manifest_digest != observed.manifest_digest
    ):
        raise StateConflictError("SSH trust source identities or freshness conflict")
    hosts = {host.logical_id: host for host in inventory.inventory.hosts}
    for entry in entries:
        host = hosts.get(entry.logical_id)
        if host is None or (
            entry.provider_id != host.provider_id
            or entry.endpoint.address != host.ansible_host
            or entry.endpoint.port != 22
            or entry.jump_host_id != host.jump_host_id
        ):
            raise StateConflictError("SSH trust host identity or route conflicts")
        if entry.jump_host_id is not None:
            jump = hosts.get(entry.jump_host_id)
            if jump is None or jump.role is not HostRole.JUMP_HOST:
                raise StateConflictError("SSH trust jump route conflicts")


def _entry_from_object(value: object) -> TrustedHostKey:
    if not isinstance(value, dict):
        raise StatePersistenceError("SSH trust entry must be an object")
    item = cast(dict[str, object], value)
    require_exact_keys(
        item,
        {
            "algorithm",
            "captured_at",
            "capture_source",
            "confirmation",
            "confirmed_at",
            "endpoint",
            "fingerprint",
            "jump_host_id",
            "logical_id",
            "provider_id",
            "public_key",
        },
        "SSH trust entry",
    )
    endpoint_value = item["endpoint"]
    if not isinstance(endpoint_value, dict):
        raise StatePersistenceError("SSH trust endpoint must be an object")
    endpoint = cast(dict[str, object], endpoint_value)
    require_exact_keys(endpoint, {"address", "port"}, "SSH trust endpoint")
    try:
        confirmation = TrustConfirmation(require_string(item, "confirmation"))
    except ValueError as error:
        raise StatePersistenceError("SSH trust confirmation is invalid") from error
    return TrustedHostKey(
        require_string(item, "logical_id"),
        require_string(item, "provider_id"),
        HostEndpoint(
            require_string(endpoint, "address"),
            _positive_integer(endpoint["port"], "SSH endpoint port"),
        ),
        _optional_string(item["jump_host_id"]),
        require_string(item, "algorithm"),
        require_string(item, "public_key"),
        require_string(item, "fingerprint"),
        require_string(item, "captured_at"),
        _capture_source(item),
        require_string(item, "confirmed_at"),
        confirmation,
    )


def _validate_identity(
    logical_id: str, provider_id: str, jump_host_id: str | None
) -> None:
    if not _LOGICAL_ID.fullmatch(logical_id):
        raise StatePersistenceError("SSH trust logical host ID is invalid")
    if not _PROVIDER_ID.fullmatch(provider_id):
        raise StatePersistenceError("SSH trust provider ID is invalid")
    if jump_host_id is not None and (
        not _LOGICAL_ID.fullmatch(jump_host_id) or jump_host_id == logical_id
    ):
        raise StatePersistenceError("SSH trust jump-host identity is invalid")


def _validate_public_key(algorithm: str, public_key: str) -> bytes:
    if algorithm not in APPROVED_HOST_KEY_ALGORITHMS:
        raise StatePersistenceError("SSH host-key algorithm is disallowed")
    if (
        not isinstance(public_key, str)
        or len(public_key) > _MAXIMUM_KEY_BLOB_BYTES * 2
        or not _BASE64.fullmatch(public_key)
    ):
        raise StatePersistenceError("SSH host-key blob is malformed")
    try:
        key = base64.b64decode(public_key, validate=True)
    except (ValueError, binascii.Error) as error:
        raise StatePersistenceError("SSH host-key blob is malformed") from error
    if not key or len(key) > _MAXIMUM_KEY_BLOB_BYTES:
        raise StatePersistenceError("SSH host-key blob is malformed")
    offset = 0
    embedded, offset = _ssh_string(key, offset)
    try:
        embedded_algorithm = embedded.decode("ascii")
    except UnicodeDecodeError as error:
        raise StatePersistenceError(
            "SSH host-key algorithm blob is malformed"
        ) from error
    if embedded_algorithm != algorithm:
        raise StateConflictError("SSH host-key algorithm and blob conflict")
    if algorithm == "ssh-ed25519":
        public, offset = _ssh_string(key, offset)
        if len(public) != 32:
            raise StatePersistenceError("SSH Ed25519 host key has invalid length")
    else:
        curve, offset = _ssh_string(key, offset)
        point, offset = _ssh_string(key, offset)
        if curve != b"nistp256" or len(point) != 65 or point[:1] != b"\x04":
            raise StatePersistenceError("SSH ECDSA host key is invalid")
    if offset != len(key):
        raise StatePersistenceError("SSH host-key blob contains trailing data")
    return key


def _ssh_string(value: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(value):
        raise StatePersistenceError("SSH host-key blob is truncated")
    size = int.from_bytes(value[offset : offset + 4], "big")
    start = offset + 4
    end = start + size
    if size < 1 or end > len(value):
        raise StatePersistenceError("SSH host-key blob is truncated")
    return value[start:end], end


def _fingerprint(key: bytes) -> str:
    encoded = base64.b64encode(hashlib.sha256(key).digest()).decode("ascii")
    return "SHA256:" + encoded.rstrip("=")


def _ssh_config_quote(value: str) -> str:
    if "\0" in value or "\n" in value or "\r" in value:
        raise StatePersistenceError("SSH configuration path is invalid")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _entries_digest(entries: tuple[TrustedHostKey, ...]) -> str:
    return digest_bytes(
        serialize_json({"entries": [entry.to_object() for entry in entries]})
    )


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")
    return value


def _capture_source(value: Mapping[str, object]) -> TrustCaptureSource:
    try:
        return TrustCaptureSource(require_string(value, "capture_source"))
    except ValueError as error:
        raise StatePersistenceError("SSH trust capture source is invalid") from error


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise StatePersistenceError("SSH trust optional string is invalid")
    return value
