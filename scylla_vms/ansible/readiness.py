"""Strict inventory-machine validation, jump routing, and readiness gates."""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.trust import StoredTrustRecord
from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import digest_bytes, serialize_json

READINESS_SCHEMA_VERSION = "deploy-scylla-vms.ansible-readiness/v1"
_SECRET_KEY = re.compile(
    r"(?:password|passwd|passphrase|private[_-]?key|secret|token|credential|vault)",
    re.IGNORECASE,
)


class EvidenceStatus(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class TrustReadiness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    CHANGED = "changed"


class RouteReadiness(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class InventoryMachineEvidence:
    list_digest: str
    graph_digest: str
    host_count: int
    group_count: int


@dataclass(frozen=True, slots=True)
class InventoryListMachineEvidence:
    """Strict normalized evidence from local ``ansible-inventory --list`` only."""

    list_digest: str
    host_count: int
    group_count: int


@dataclass(frozen=True, slots=True)
class RouteReport:
    status: RouteReadiness
    direct_hosts: int
    proxied_hosts: int
    jump_hosts: int
    findings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    source_status: EvidenceStatus
    machine_status: EvidenceStatus
    trust_status: TrustReadiness
    route_status: RouteReadiness
    observation_generation: int | None
    observation_digest: str | None
    inventory_generation: int | None
    inventory_digest: str | None
    trust_generation: int | None
    trust_digest: str | None
    host_count: int
    trusted_host_count: int
    fingerprints: tuple[tuple[str, str, str, str, str], ...]
    route: RouteReport
    blockers: tuple[tuple[OperationClassification, tuple[str, ...]], ...]
    schema_version: str = READINESS_SCHEMA_VERSION

    @property
    def status(self) -> EvidenceStatus:
        if (
            self.source_status is EvidenceStatus.CONFLICT
            or self.machine_status is EvidenceStatus.CONFLICT
            or self.trust_status is TrustReadiness.CHANGED
            or self.route_status is RouteReadiness.INVALID
        ):
            return EvidenceStatus.CONFLICT
        if self.source_status is EvidenceStatus.STALE:
            return EvidenceStatus.STALE
        if (
            self.source_status is EvidenceStatus.UNKNOWN
            or self.machine_status is EvidenceStatus.UNKNOWN
            or self.trust_status is TrustReadiness.INCOMPLETE
            or self.route_status is RouteReadiness.UNKNOWN
        ):
            return EvidenceStatus.UNKNOWN
        return EvidenceStatus.FRESH

    def blockers_for(self, classification: OperationClassification) -> tuple[str, ...]:
        return dict(self.blockers)[classification]

    def require_ready(self, classification: OperationClassification) -> None:
        blockers = self.blockers_for(classification)
        if blockers:
            raise StateConflictError(
                "Ansible readiness gate is unsatisfied: " + ",".join(blockers)
            )

    def to_public_object(self) -> dict[str, object]:
        """Project no addresses, provider IDs, key blobs, or paths."""

        return {
            "blockers": {
                classification.value: list(values)
                for classification, values in self.blockers
            },
            "fingerprints": [
                {
                    "algorithm": algorithm,
                    "capture_source": capture_source,
                    "confirmation": confirmation,
                    "fingerprint": fingerprint,
                    "logical_id": logical_id,
                }
                for (
                    logical_id,
                    algorithm,
                    fingerprint,
                    capture_source,
                    confirmation,
                ) in self.fingerprints
            ],
            "host_count": self.host_count,
            "inventory": {
                "digest": self.inventory_digest,
                "generation": self.inventory_generation,
            },
            "machine_status": self.machine_status.value,
            "observation": {
                "digest": self.observation_digest,
                "generation": self.observation_generation,
            },
            "route": {
                "direct_hosts": self.route.direct_hosts,
                "findings": list(self.route.findings),
                "jump_hosts": self.route.jump_hosts,
                "proxied_hosts": self.route.proxied_hosts,
                "status": self.route_status.value,
            },
            "schema_version": self.schema_version,
            "source_status": self.source_status.value,
            "status": self.status.value,
            "trust": {
                "digest": self.trust_digest,
                "generation": self.trust_generation,
                "status": self.trust_status.value,
                "trusted_host_count": self.trusted_host_count,
            },
        }


def validate_inventory_machine_output(
    listed: str | bytes,
    graphed: str | bytes,
    expected: StoredInventoryRecord,
    *,
    maximum_bytes: int = 4 * 1024 * 1024,
    protected_values: tuple[str, ...] = (),
) -> InventoryMachineEvidence:
    """Prove Ansible preserved exact hosts, groups, hostvars, and safe variables."""

    listed_evidence = validate_inventory_list_output(
        listed,
        expected,
        maximum_bytes=maximum_bytes,
        protected_values=protected_values,
    )
    graph_bytes = _bytes(graphed, maximum_bytes, "graph")
    _validate_graph(graph_bytes, expected)
    return InventoryMachineEvidence(
        listed_evidence.list_digest,
        digest_bytes(graph_bytes),
        listed_evidence.host_count,
        listed_evidence.group_count,
    )


def validate_inventory_list_output(
    listed: str | bytes,
    expected: StoredInventoryRecord,
    *,
    maximum_bytes: int = 4 * 1024 * 1024,
    protected_values: tuple[str, ...] = (),
) -> InventoryListMachineEvidence:
    """Prove exact normalized inventory parity without contacting any host."""

    listed_bytes = _bytes(listed, maximum_bytes, "list")
    try:
        value = json.loads(
            listed_bytes.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AnsibleError("ansible-inventory returned malformed JSON") from error
    if not isinstance(value, dict):
        raise AnsibleError("ansible-inventory list output must be an object")
    _reject_secret_keys(value)
    actual = cast(dict[str, object], value)
    expected_object = expected.record.to_machine_object()
    if protected_values:
        expected_object = cast(
            dict[str, object],
            _redact_expected(expected_object, protected_values),
        )
    expected_hostvars = cast(
        dict[str, object],
        cast(dict[str, object], expected_object["_meta"])["hostvars"],
    )
    actual_meta = actual.get("_meta")
    if not isinstance(actual_meta, dict) or not isinstance(
        actual_meta.get("hostvars"), dict
    ):
        raise AnsibleError("ansible-inventory omitted hostvars")
    if set(actual_meta) not in ({"hostvars"}, {"hostvars", "profile"}) or (
        "profile" in actual_meta and actual_meta["profile"] != "inventory_legacy"
    ):
        raise StateConflictError("ansible-inventory metadata conflicts")
    expected_all = cast(dict[str, object], expected_object["all"])
    expected_all_vars = cast(dict[str, object], expected_all["vars"])
    expanded_hostvars = {
        logical_id: {
            **expected_all_vars,
            **cast(dict[str, object], hostvars),
        }
        for logical_id, hostvars in expected_hostvars.items()
    }
    if actual_meta["hostvars"] not in (expected_hostvars, expanded_hostvars):
        raise StateConflictError("ansible-inventory hostvars conflict")
    expected_groups = {
        group.name: list(group.hosts) for group in expected.record.inventory.groups
    }
    expected_names = {"_meta", "all", *expected_groups}
    if not set(actual) <= expected_names | {"ungrouped"} or not {
        "_meta",
        "all",
    } <= set(actual):
        raise StateConflictError("ansible-inventory groups conflict")
    for name, hosts in expected_groups.items():
        group = actual.get(name)
        if group is None and not hosts:
            continue
        if not isinstance(group, dict) or set(group) != {"hosts"}:
            raise StateConflictError("ansible-inventory group shape conflicts")
        if group["hosts"] != hosts:
            raise StateConflictError("ansible-inventory group membership conflicts")
    ungrouped = actual.get("ungrouped")
    if ungrouped is not None and ungrouped != {"hosts": []}:
        raise StateConflictError("ansible-inventory contains ungrouped hosts")
    actual_all = actual["all"]
    if not isinstance(actual_all, dict) or set(actual_all) not in (
        {"children"},
        {"children", "vars"},
    ):
        raise StateConflictError("ansible-inventory all-group shape conflicts")
    children = actual_all["children"]
    if (
        not isinstance(children, list)
        or not all(isinstance(item, str) for item in children)
        or len(children) != len(set(children))
        or set(children) not in (set(expected_groups), {*expected_groups, "ungrouped"})
    ):
        raise StateConflictError("ansible-inventory all-group variables conflict")
    if "vars" in actual_all:
        if actual_all["vars"] != expected_all_vars:
            raise StateConflictError("ansible-inventory all-group variables conflict")
    elif actual_meta["hostvars"] != expanded_hostvars:
        raise StateConflictError("ansible-inventory inherited variables conflict")
    return InventoryListMachineEvidence(
        digest_bytes(serialize_json(actual)),
        len(expected_hostvars),
        len(expected_groups),
    )


def validate_routes(
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord | None,
) -> RouteReport:
    hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
    jumps = tuple(
        sorted(
            host.logical_id
            for host in hosts.values()
            if host.role is HostRole.JUMP_HOST
        )
    )
    trusted = (
        {entry.logical_id: entry for entry in trust.record.entries}
        if trust is not None
        else {}
    )
    findings: list[str] = []
    direct = 0
    proxied = 0
    for logical_id in sorted(hosts):
        host = hosts[logical_id]
        entry = trusted.get(logical_id)
        if host.role is not HostRole.JUMP_HOST and host.public_address is not None:
            findings.append(f"{logical_id}:private-role-public-address")
        if host.jump_host_id is None:
            direct += 1
            if host.role is not HostRole.JUMP_HOST and jumps:
                findings.append(f"{logical_id}:missing-jump")
        else:
            proxied += 1
            jump = hosts.get(host.jump_host_id)
            if (
                jump is None
                or jump.role is not HostRole.JUMP_HOST
                or jump.jump_host_id is not None
                or host.jump_host_id == logical_id
            ):
                findings.append(f"{logical_id}:invalid-jump")
            elif jumps and host.jump_host_id != _selected_jump(logical_id, jumps):
                findings.append(f"{logical_id}:ambiguous-jump-policy")
            if trust is not None and host.jump_host_id not in trusted:
                findings.append(f"{logical_id}:untrusted-jump")
        if entry is not None and (
            entry.provider_id != host.provider_id
            or entry.endpoint.address != host.ansible_host
            or entry.jump_host_id != host.jump_host_id
        ):
            findings.append(f"{logical_id}:trust-route-identity-changed")
    status = (
        RouteReadiness.INVALID
        if findings
        else RouteReadiness.UNKNOWN
        if trust is None
        else RouteReadiness.VALID
    )
    return RouteReport(
        status,
        direct,
        proxied,
        len(jumps),
        tuple(sorted(set(findings))),
    )


def build_readiness_report(
    observed: StoredObservedState | None,
    inventory: StoredInventoryRecord | None,
    trust: StoredTrustRecord | None,
    *,
    machine_evidence: InventoryMachineEvidence
    | InventoryListMachineEvidence
    | None = None,
    machine_conflict: bool = False,
    trust_conflict: bool = False,
) -> ReadinessReport:
    if inventory is None:
        route = RouteReport(RouteReadiness.UNKNOWN, 0, 0, 0, ("inventory-unavailable",))
        source_status = EvidenceStatus.UNKNOWN
        host_count = 0
    elif observed is None:
        route = validate_routes(inventory, trust)
        source_status = EvidenceStatus.UNKNOWN
        host_count = len(inventory.record.inventory.hosts)
    else:
        source_status = (
            EvidenceStatus.FRESH
            if inventory.record.source_manifest_generation == observed.record.generation
            and inventory.record.source_manifest_digest
            == observed.record.manifest_digest
            else EvidenceStatus.STALE
        )
        route = validate_routes(inventory, trust)
        host_count = len(inventory.record.inventory.hosts)
    machine_status = (
        EvidenceStatus.CONFLICT
        if machine_conflict
        else EvidenceStatus.FRESH
        if machine_evidence is not None
        else EvidenceStatus.UNKNOWN
    )
    fingerprints: tuple[tuple[str, str, str, str, str], ...]
    if trust_conflict:
        trust_status = TrustReadiness.CHANGED
        trusted_count = 0
        fingerprints = ()
        route = RouteReport(
            RouteReadiness.INVALID,
            route.direct_hosts,
            route.proxied_hosts,
            route.jump_hosts,
            tuple(sorted((*route.findings, "trust-runtime-conflict"))),
        )
    elif trust is None or inventory is None:
        trust_status = TrustReadiness.INCOMPLETE
        trusted_count = 0
        fingerprints = ()
    else:
        host_ids = {host.logical_id for host in inventory.record.inventory.hosts}
        trust_ids = {entry.logical_id for entry in trust.record.entries}
        fresh = observed is not None and trust.record.is_fresh_for(
            observed.record, inventory.record
        )
        if not fresh:
            trust_status = TrustReadiness.CHANGED
        elif trust_ids != host_ids:
            trust_status = TrustReadiness.INCOMPLETE
        else:
            trust_status = TrustReadiness.COMPLETE
        trusted_count = len(trust_ids & host_ids)
        fingerprints = tuple(
            (
                entry.logical_id,
                entry.algorithm,
                entry.fingerprint,
                entry.capture_source.value,
                entry.confirmation.value,
            )
            for entry in trust.record.entries
            if entry.logical_id in host_ids
        )
    common: list[str] = []
    if source_status is not EvidenceStatus.FRESH:
        common.append(f"source-{source_status.value}")
    if machine_status is not EvidenceStatus.FRESH:
        common.append(f"inventory-machine-{machine_status.value}")
    if trust_status is not TrustReadiness.COMPLETE:
        common.append(f"trust-{trust_status.value}")
    if route.status is not RouteReadiness.VALID:
        common.append(f"route-{route.status.value}")
    blockers = tuple(
        (classification, tuple(common)) for classification in OperationClassification
    )
    return ReadinessReport(
        source_status,
        machine_status,
        trust_status,
        route.status,
        observed.record.generation if observed else None,
        observed.record.manifest_digest if observed else None,
        inventory.record.generation if inventory else None,
        inventory.digest if inventory else None,
        trust.record.generation if trust else None,
        trust.digest if trust else None,
        host_count,
        trusted_count,
        fingerprints,
        route,
        blockers,
    )


def validate_current_readiness_report(
    report: ReadinessReport,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
) -> None:
    """Validate an already-established machine-ready report against local state."""

    if not isinstance(report, ReadinessReport) or (
        report.machine_status is not EvidenceStatus.FRESH
    ):
        raise StateConflictError(
            "Ansible readiness requires established fresh machine validation"
        )
    # Machine-output digests are deliberately not part of ReadinessReport. This
    # marker preserves the caller's established fresh status while rebuilding
    # every local-state-derived field for exact comparison.
    marker_digest = digest_bytes(b"readiness-machine-evidence-present")
    expected = build_readiness_report(
        observed,
        inventory,
        trust,
        machine_evidence=InventoryMachineEvidence(
            marker_digest,
            marker_digest,
            len(inventory.record.inventory.hosts),
            len(inventory.record.inventory.groups),
        ),
    )
    if report != expected:
        raise StateConflictError("Ansible readiness or canonical evidence drifted")


def _selected_jump(logical_id: str, jump_ids: tuple[str, ...]) -> str:
    index = int(hashlib.sha256(logical_id.encode("utf-8")).hexdigest()[:8], 16)
    return jump_ids[index % len(jump_ids)]


def _validate_graph(data: bytes, expected: StoredInventoryRecord) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AnsibleError("ansible-inventory graph output is not UTF-8") from error
    expected_hosts = {host.logical_id for host in expected.record.inventory.hosts}
    expected_groups = {group.name for group in expected.record.inventory.groups}
    allowed_groups = expected_groups | {"ungrouped"}
    found_hosts: set[str] = set()
    found_groups: set[str] = set()
    for raw in text.splitlines():
        token = re.sub(r"^[| \-]+", "", raw).strip()
        if token == "@all:":
            continue
        if token.startswith("@") and token.endswith(":"):
            name = token[1:-1]
            if name not in allowed_groups:
                raise StateConflictError("ansible-inventory graph has an unknown group")
            if name != "ungrouped":
                found_groups.add(name)
        elif token:
            if token not in expected_hosts:
                raise StateConflictError("ansible-inventory graph has an unknown host")
            found_hosts.add(token)
    if found_hosts != expected_hosts or found_groups != expected_groups:
        raise StateConflictError("ansible-inventory graph membership conflicts")


def _bytes(value: str | bytes, maximum: int, label: str) -> bytes:
    data = value.encode("utf-8") if isinstance(value, str) else value
    if len(data) > maximum:
        raise AnsibleError(f"ansible-inventory {label} output exceeds size limit")
    return data


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("ansible-inventory output contains duplicate keys")
        value[key] = item
    return value


def _reject_secret_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or _SECRET_KEY.search(key):
                raise StateConflictError(
                    "ansible-inventory output contains unsafe variable keys"
                )
            _reject_secret_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_keys(item)


def _redact_expected(value: object, protected_values: tuple[str, ...]) -> object:
    if isinstance(value, dict):
        return {
            key: _redact_expected(item, protected_values) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_expected(item, protected_values) for item in value]
    if isinstance(value, str):
        for protected in protected_values:
            value = value.replace(protected, "[REDACTED]")
    return value
