"""Deterministic desired-versus-observed cluster reconciliation."""

from dataclasses import dataclass
from enum import StrEnum

from scylla_vms.desired import ClusterSpec, HostRole, StorageBackend, StoragePolicy
from scylla_vms.terraform.outputs import TerraformHost, TerraformHostManifest


class ReconciliationClass(StrEnum):
    MATCH = "match"
    INTENDED_CHANGE = "intended-change"
    DRIFT = "drift"
    UNKNOWN = "unknown"
    SENSITIVE_CONFLICT = "sensitive-conflict"


@dataclass(frozen=True, slots=True)
class ReconciliationFinding:
    finding_class: ReconciliationClass
    code: str
    logical_id: str | None
    field: str


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    findings: tuple[ReconciliationFinding, ...]
    desired_host_count: int
    observed_host_count: int

    @property
    def status(self) -> ReconciliationClass:
        classes = {finding.finding_class for finding in self.findings}
        for candidate in (
            ReconciliationClass.SENSITIVE_CONFLICT,
            ReconciliationClass.DRIFT,
            ReconciliationClass.UNKNOWN,
            ReconciliationClass.INTENDED_CHANGE,
        ):
            if candidate in classes:
                return candidate
        return ReconciliationClass.MATCH

    @property
    def conflict_free(self) -> bool:
        return self.status not in {
            ReconciliationClass.SENSITIVE_CONFLICT,
            ReconciliationClass.DRIFT,
        }

    @property
    def sensitive_ready(self) -> bool:
        return self.status is ReconciliationClass.MATCH


@dataclass(frozen=True, slots=True)
class _ExpectedHost:
    role: HostRole
    zone: str
    shape: str
    datacenter: str | None
    rack: str | None
    storage: StoragePolicy


def reconcile_desired_observed(
    spec: ClusterSpec,
    manifest: TerraformHostManifest | None,
    *,
    baseline: TerraformHostManifest | None = None,
    intended_additions: frozenset[str] = frozenset(),
    intended_removals: frozenset[str] = frozenset(),
) -> ReconciliationReport:
    """Compare immutable desired and observed models without selecting a winner."""

    expected = _expected_hosts(spec)
    if manifest is None:
        return ReconciliationReport(
            (
                ReconciliationFinding(
                    ReconciliationClass.UNKNOWN,
                    "manifest-not-observed",
                    None,
                    "manifest",
                ),
            ),
            len(expected),
            0,
        )
    if manifest.cluster_uuid != spec.cluster_uuid:
        return ReconciliationReport(
            (
                ReconciliationFinding(
                    ReconciliationClass.SENSITIVE_CONFLICT,
                    "cluster-identity-conflict",
                    None,
                    "cluster_uuid",
                ),
            ),
            len(expected),
            len(manifest.hosts),
        )
    unknown_intent = (intended_additions | intended_removals) - (
        set(expected) | {host.logical_id for host in manifest.hosts}
    )
    if unknown_intent:
        raise ValueError("intended host sets contain unknown logical IDs")
    observed = {host.logical_id: host for host in manifest.hosts}
    findings: list[ReconciliationFinding] = []
    for logical_id in sorted(set(expected) - set(observed)):
        finding_class = (
            ReconciliationClass.INTENDED_CHANGE
            if logical_id in intended_additions
            else ReconciliationClass.UNKNOWN
        )
        findings.append(
            ReconciliationFinding(
                finding_class,
                "intended-addition"
                if logical_id in intended_additions
                else "host-not-observed",
                logical_id,
                "membership",
            )
        )
    for logical_id in sorted(set(observed) - set(expected)):
        finding_class = (
            ReconciliationClass.INTENDED_CHANGE
            if logical_id in intended_removals
            else ReconciliationClass.SENSITIVE_CONFLICT
        )
        findings.append(
            ReconciliationFinding(
                finding_class,
                "intended-removal"
                if logical_id in intended_removals
                else "unexpected-host",
                logical_id,
                "membership",
            )
        )
    baseline_hosts = (
        {host.logical_id: host for host in baseline.hosts}
        if baseline is not None
        else {}
    )
    for logical_id in sorted(set(expected) & set(observed)):
        host = observed[logical_id]
        desired = expected[logical_id]
        _compare_identity(findings, logical_id, desired, host)
        _compare_storage(findings, logical_id, desired.storage, host)
        previous = baseline_hosts.get(logical_id)
        if previous is not None:
            _compare_observed_identity(findings, logical_id, previous, host)
    if not findings:
        findings.append(
            ReconciliationFinding(
                ReconciliationClass.MATCH,
                "desired-observed-match",
                None,
                "cluster",
            )
        )
    return ReconciliationReport(
        tuple(
            sorted(
                findings,
                key=lambda item: (
                    item.finding_class.value,
                    item.logical_id or "",
                    item.field,
                    item.code,
                ),
            )
        ),
        len(expected),
        len(manifest.hosts),
    )


def _expected_hosts(spec: ClusterSpec) -> dict[str, _ExpectedHost]:
    policies = {policy.role: policy for policy in spec.storage}
    expected: dict[str, _ExpectedHost] = {}
    for zone_spec in spec.zones:
        for logical_id in zone_spec.logical_node_ids:
            expected[logical_id] = _ExpectedHost(
                HostRole.SCYLLA,
                zone_spec.zone_id,
                spec.scylla_instance_type,
                spec.scylla_datacenter.value,
                zone_spec.scylla_rack.value,
                policies[HostRole.SCYLLA],
            )
    for service in spec.services:
        if service.instance_type is None:
            continue
        for logical_id, zone in zip(service.logical_ids, service.zones, strict=True):
            expected[logical_id] = _ExpectedHost(
                service.role,
                zone,
                service.instance_type,
                None,
                None,
                policies[service.role],
            )
    return expected


def _compare_identity(
    findings: list[ReconciliationFinding],
    logical_id: str,
    desired: _ExpectedHost,
    observed: TerraformHost,
) -> None:
    sensitive_fields = (
        ("role", desired.role.value, observed.role.value),
        ("zone", desired.zone, observed.zone),
        ("scylla_datacenter", desired.datacenter, observed.scylla_datacenter),
        ("scylla_rack", desired.rack, observed.scylla_rack),
    )
    for field, expected, actual in sensitive_fields:
        if expected != actual:
            findings.append(
                ReconciliationFinding(
                    ReconciliationClass.SENSITIVE_CONFLICT,
                    f"{field}-conflict",
                    logical_id,
                    field,
                )
            )
    if desired.shape != observed.shape:
        findings.append(
            ReconciliationFinding(
                ReconciliationClass.DRIFT,
                "shape-drift",
                logical_id,
                "shape",
            )
        )


def _compare_storage(
    findings: list[ReconciliationFinding],
    logical_id: str,
    policy: StoragePolicy,
    observed: TerraformHost,
) -> None:
    storage = observed.storage
    conflict = storage.requested_backend is not policy.requested_backend
    if policy.requested_backend is not StorageBackend.AUTO:
        conflict = conflict or storage.selected_backend is not policy.requested_backend
    if (
        policy.block_volume is not None
        and storage.selected_backend is StorageBackend.BLOCK_VOLUME
    ):
        conflict = conflict or (
            storage.expected_device_count != policy.block_volume.count
            or storage.raw_total_gib
            != policy.block_volume.count * policy.block_volume.size_gib
        )
    if storage.selected_backend is StorageBackend.LOCAL_NVME:
        minimum_count = policy.local_min_device_count or 0
        minimum_total = policy.local_min_total_gib or 0
        conflict = conflict or (
            storage.expected_device_count < minimum_count
            or storage.usable_total_gib < minimum_total
            or not all(device.ephemeral for device in storage.devices)
        )
    if conflict:
        findings.append(
            ReconciliationFinding(
                ReconciliationClass.SENSITIVE_CONFLICT,
                "storage-policy-conflict",
                logical_id,
                "storage",
            )
        )


def _compare_observed_identity(
    findings: list[ReconciliationFinding],
    logical_id: str,
    previous: TerraformHost,
    current: TerraformHost,
) -> None:
    sensitive = (
        ("provider_id", previous.provider_id, current.provider_id),
        ("storage", _storage_identity(previous), _storage_identity(current)),
    )
    for field, before, after in sensitive:
        if before != after:
            findings.append(
                ReconciliationFinding(
                    ReconciliationClass.SENSITIVE_CONFLICT,
                    f"{field}-changed",
                    logical_id,
                    field,
                )
            )
    for changed_field, prior_value, current_value in (
        ("private_address", previous.private_address, current.private_address),
        ("public_address", previous.public_address, current.public_address),
        ("jump_host_id", previous.jump_host_id, current.jump_host_id),
    ):
        if prior_value != current_value:
            findings.append(
                ReconciliationFinding(
                    ReconciliationClass.DRIFT,
                    f"{changed_field}-changed",
                    logical_id,
                    changed_field,
                )
            )


def _storage_identity(host: TerraformHost) -> tuple[object, ...]:
    storage = host.storage
    return (
        storage.selected_backend,
        storage.policy_digest,
        storage.storage_generation,
        storage.expected_device_count,
        storage.raw_total_gib,
        storage.usable_total_gib,
        tuple(
            (
                device.kind,
                device.provider_volume_id,
                device.provider_attachment_id,
                device.local_device_id,
                device.expected_serial,
                device.expected_wwn,
                device.expected_by_id,
                device.size_gib,
                device.ephemeral,
            )
            for device in storage.devices
        ),
    )
