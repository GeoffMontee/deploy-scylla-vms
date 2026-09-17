"""Guarded read-only jump-host connectivity operation."""

import ipaddress
import json
import math
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO, cast

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.service import (
    AnsibleService,
    ConnectivityEvidence,
    ConnectivityStatus,
    DestinationProbeStatus,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.desired import HostRole, resolve_existing_config
from scylla_vms.errors import (
    AnsibleError,
    ConfigurationError,
    ExitCode,
    OperationNotImplementedError,
    StateConflictError,
    ToolPrerequisiteError,
)
from scylla_vms.inventory import InventoryHost, InventoryStore, StoredInventoryRecord
from scylla_vms.locking import ClusterReadLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    format_timestamp,
)
from scylla_vms.process import (
    ProcessResult,
    ProcessRunner,
    ProcessSpec,
    ProcessTimeoutError,
)
from scylla_vms.reconciliation import ReconciliationClass, reconcile_desired_observed
from scylla_vms.state import (
    refuse_unexpected_terraform_state,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.validation import DESTINATION_CHECK_PORTS

CHECK_JUMP_HOSTS_SCHEMA_VERSION = "deploy-scylla-vms.check-jump-hosts/v2"
_MAX_SELECTED_JUMP_HOSTS = 16
_MAX_DESTINATION_PROBES = 64


@dataclass(frozen=True, slots=True)
class JumpHostCheckRow:
    logical_id: str
    zone: str
    route_mode: str
    trust: str
    connectivity: str

    def to_object(self) -> dict[str, str]:
        return {
            "connectivity": self.connectivity,
            "logical_id": self.logical_id,
            "route_mode": self.route_mode,
            "trust": self.trust,
            "zone": self.zone,
        }


@dataclass(frozen=True, slots=True)
class DestinationProbe:
    jump_host_id: str
    target_logical_id: str
    role: str
    address: str
    port: int

    def to_variable(self) -> dict[str, object]:
        return {
            "address": self.address,
            "jump_host_id": self.jump_host_id,
            "port": self.port,
            "role": self.role,
            "target_logical_id": self.target_logical_id,
        }


@dataclass(frozen=True, slots=True)
class DestinationProbeRow:
    jump_host_id: str
    target_logical_id: str
    role: str
    port: int
    protocol: str
    status: str

    def to_object(self) -> dict[str, object]:
        return {
            "jump_host_id": self.jump_host_id,
            "port": self.port,
            "protocol": self.protocol,
            "role": self.role,
            "status": self.status,
            "target_logical_id": self.target_logical_id,
        }


@dataclass(frozen=True, slots=True)
class JumpHostCheckReport:
    generated_at: str
    cluster: dict[str, str]
    selection: dict[str, object]
    provenance: dict[str, object]
    checks: dict[str, str]
    jumps: tuple[JumpHostCheckRow, ...]
    destination_probes: tuple[DestinationProbeRow, ...]
    exit_code: ExitCode

    def to_object(self) -> dict[str, object]:
        return {
            "checks": self.checks,
            "cluster": self.cluster,
            "destination_probes": [
                probe.to_object() for probe in self.destination_probes
            ],
            "exit_status": {"code": int(self.exit_code)},
            "generated_at": self.generated_at,
            "jumps": [row.to_object() for row in self.jumps],
            "provenance": self.provenance,
            "schema_version": CHECK_JUMP_HOSTS_SCHEMA_VERSION,
            "selection": self.selection,
        }


@dataclass(frozen=True, slots=True)
class JumpHostState:
    cluster: StoredClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    selected: tuple[InventoryHost, ...]
    depth: str
    destinations: tuple[str, ...]
    probes: tuple[DestinationProbe, ...]


@dataclass(frozen=True, slots=True)
class JumpHostOperationSelection:
    """Inventory-derived plan inputs without copying them into durable context."""

    selected: tuple[InventoryHost, ...]
    depth: str
    destinations: tuple[str, ...]
    probes: tuple[DestinationProbe, ...]


class _DeadlineRunner:
    def __init__(
        self,
        runner: ProcessRunnerProtocol,
        timeout_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._runner = runner
        self._deadline = monotonic() + timeout_seconds
        self._monotonic = monotonic

    def run(self, spec: ProcessSpec) -> ProcessResult:
        remaining = self._deadline - self._monotonic()
        if remaining <= 0:
            raise ProcessTimeoutError("jump-host check exceeded its total timeout")
        return self._runner.run(
            replace(spec, timeout_seconds=min(spec.timeout_seconds, remaining))
        )


def run_check_jump_hosts(
    request: OperationRequest,
    output: TextIO,
    *,
    runner: ProcessRunnerProtocol | None = None,
    playbook_executable: Path | None = None,
    inventory_executable: Path | None = None,
    clock: Callable[[], datetime] | None = None,
) -> int:
    """Validate local evidence, then perform bounded jump-only checks."""

    if request.operation.name != "check-jump-hosts":
        raise ConfigurationError(
            "jump-host checker requires a check-jump-hosts request"
        )
    _reject_unavailable_scope(request)
    timeout = _number(request, "check_timeout_seconds")
    deadline_runner = _DeadlineRunner(runner or ProcessRunner(), timeout)
    with ClusterReadLock(
        request.paths, _number(request, "lock_timeout_seconds")
    ) as lock:
        state = _load_state(request, lock)
        if not state.selected:
            report = _report(
                state,
                None,
                None,
                generated_at=format_timestamp((clock or _utc_now)()),
            )
        else:
            service = AnsibleService(
                AnsibleCommandBuilder(
                    playbook_executable or _sibling_executable("ansible-playbook"),
                    inventory_executable or _sibling_executable("ansible-inventory"),
                    request.paths,
                    timeout_seconds=timeout,
                ),
                deadline_runner,
            )
            service.version(lock)
            readiness = service.validate_inventory(
                lock, state.observed, state.inventory, state.trust
            )
            readiness.require_ready(OperationClassification.READ_ONLY)
            selected_ids = tuple(host.logical_id for host in state.selected)
            try:
                service.execute(
                    lock,
                    state.cluster.record,
                    state.inventory,
                    "inventory-preflight",
                    limit=selected_ids,
                    variables={},
                    readiness=readiness,
                    check=True,
                )
            except AnsibleError as error:
                report = _report(
                    state,
                    readiness,
                    None,
                    generated_at=format_timestamp((clock or _utc_now)()),
                    preflight=_failure_kind(error),
                )
            else:
                try:
                    connectivity_result = service.execute(
                        lock,
                        state.cluster.record,
                        state.inventory,
                        "connectivity-check",
                        limit=selected_ids,
                        variables={
                            "deploy_scylla_vms_connect_timeout_seconds": _number(
                                request, "connect_timeout_seconds"
                            ),
                            "deploy_scylla_vms_destination_probes": [
                                probe.to_variable() for probe in state.probes
                            ],
                            "deploy_scylla_vms_probe_timeout_seconds": max(
                                1,
                                math.ceil(_number(request, "connect_timeout_seconds")),
                            ),
                        },
                        readiness=readiness,
                        check=True,
                    )
                    connectivity = connectivity_result.connectivity
                    if connectivity is None:
                        raise AnsibleError(
                            "Ansible connectivity evidence is unavailable"
                        )
                    report = _report(
                        state,
                        readiness,
                        connectivity,
                        generated_at=format_timestamp((clock or _utc_now)()),
                    )
                except AnsibleError as error:
                    report = _report(
                        state,
                        readiness,
                        None,
                        generated_at=format_timestamp((clock or _utc_now)()),
                        connectivity_failure=_failure_kind(error),
                    )
        output.write(
            render_check_jump_hosts_json(report)
            if _boolean(request, "json")
            else render_check_jump_hosts_human(report)
        )
    return int(report.exit_code)


def _load_state(request: OperationRequest, lock: ClusterReadLock) -> JumpHostState:
    lock.assert_held_for(request.paths)
    for directory in (
        request.paths.state_root,
        request.paths.clusters,
        request.paths.cluster_root,
        request.paths.terraform,
        request.paths.ansible,
        request.paths.ansible_home,
        request.paths.ansible_local_tmp,
        request.paths.ansible_fact_cache,
        request.paths.ansible_control_path,
        request.paths.logs,
    ):
        validate_state_directory(directory)
    refuse_unexpected_terraform_state(request.paths, (request.paths.cluster_root,))
    cluster = ClusterMetadataStore(request.paths).read(
        expected_cluster_name=request.cluster_name,
        expected_provider=request.provider.name,
    )
    resolve_existing_config(request, cluster.record.desired_spec)
    for path in (
        request.paths.terraform_observed,
        request.paths.ansible_inventory,
        request.paths.ansible_trust,
        request.paths.known_hosts,
        request.paths.ansible_ssh_config,
        request.paths.ansible_config,
    ):
        validate_state_file(path)
    observed = ObservedStateStore(request.paths).read(
        expected_cluster_uuid=cluster.record.cluster_uuid,
        expected_cluster_name=cluster.record.cluster_name,
        expected_provider=cluster.record.provider,
    )
    inventory = InventoryStore(request.paths).read(
        expected_cluster_uuid=cluster.record.cluster_uuid,
        expected_cluster_name=cluster.record.cluster_name,
        expected_provider=cluster.record.provider,
    )
    trust = TrustStore(request.paths).read(
        expected_cluster_uuid=cluster.record.cluster_uuid,
        expected_cluster_name=cluster.record.cluster_name,
        expected_provider=cluster.record.provider,
    )
    if (
        inventory.record.source_manifest_generation != observed.record.generation
        or inventory.record.source_manifest_digest != observed.record.manifest_digest
    ):
        raise StateConflictError("jump-host inventory is stale")
    reconciliation = reconcile_desired_observed(
        cluster.record.desired_spec, observed.record.manifest
    )
    if reconciliation.status is not ReconciliationClass.MATCH:
        raise StateConflictError("jump-host state reconciliation is not clean")
    TrustStore(request.paths).validate_runtime(trust, inventory)
    if not trust.record.is_fresh_for(observed.record, inventory.record):
        raise StateConflictError("jump-host trust is stale")
    selection = resolve_jump_host_operation_selection(request, inventory)
    return JumpHostState(
        cluster,
        observed,
        inventory,
        trust,
        selection.selected,
        selection.depth,
        selection.destinations,
        selection.probes,
    )


def resolve_jump_host_operation_selection(
    request: OperationRequest,
    inventory: StoredInventoryRecord,
) -> JumpHostOperationSelection:
    """Derive exact selected hosts and address-bearing probes from current inventory."""

    if request.operation.name != "check-jump-hosts":
        raise ConfigurationError(
            "jump-host selection requires a check-jump-hosts request"
        )
    jumps = tuple(
        host
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.JUMP_HOST
    )
    selected_ids = _strings(request, "jump_host")
    by_id = {host.logical_id: host for host in jumps}
    unknown = sorted(set(selected_ids) - set(by_id))
    if unknown:
        raise ConfigurationError(
            "unknown or non-jump --jump-host stable ID: " + ", ".join(unknown)
        )
    selected = (
        tuple(by_id[logical_id] for logical_id in selected_ids)
        if selected_ids
        else jumps
    )
    if len(selected) > _MAX_SELECTED_JUMP_HOSTS:
        raise ConfigurationError(
            f"jump-host selection exceeds {_MAX_SELECTED_JUMP_HOSTS} hosts"
        )
    depth = cast(str, request.option("depth").value)
    destinations = _strings(request, "destination")
    probes = _destination_probes(
        request, selected, inventory, depth=depth, destinations=destinations
    )
    return JumpHostOperationSelection(
        selected,
        depth,
        destinations,
        probes,
    )


def _destination_probes(
    request: OperationRequest,
    selected: tuple[InventoryHost, ...],
    inventory: StoredInventoryRecord,
    *,
    depth: str,
    destinations: tuple[str, ...],
) -> tuple[DestinationProbe, ...]:
    checks = _integer_map(request, "destination_check")
    if not checks:
        if depth == "all-targets":
            raise OperationNotImplementedError(
                "--depth all-targets without --destination-check requires "
                "unavailable private-target SSH checks; no checks were performed"
            )
        return ()
    if depth == "bastion":
        raise ConfigurationError(
            "--destination-check requires --depth route or --depth all-targets"
        )
    selected_roles = (
        set(DESTINATION_CHECK_PORTS)
        if "assigned" in destinations or "all" in destinations
        else set(destinations)
    )
    if not set(checks).issubset(selected_roles):
        raise ConfigurationError(
            "--destination-check role is excluded by --destination"
        )
    selected_ids = {host.logical_id for host in selected}
    candidates = tuple(
        host
        for host in inventory.record.inventory.hosts
        if host.role is not HostRole.JUMP_HOST
        and host.role.value in checks
        and host.jump_host_id in selected_ids
        and host.route_mode == "proxy-jump"
        and host.ansible_host == host.private_address
        and _is_rfc1918(host.private_address)
    )
    resolved_roles = {host.role.value for host in candidates}
    missing_roles = sorted(set(checks) - resolved_roles)
    if missing_roles:
        raise ConfigurationError(
            "destination role has no policy-reachable inventory target: "
            + ", ".join(missing_roles)
        )
    probes: list[DestinationProbe] = []
    for jump in selected:
        by_role: dict[str, list[InventoryHost]] = {}
        for host in candidates:
            if host.jump_host_id == jump.logical_id:
                by_role.setdefault(host.role.value, []).append(host)
        for role in sorted(checks):
            role_hosts = sorted(by_role.get(role, []), key=lambda host: host.logical_id)
            if depth == "route":
                role_hosts = role_hosts[:1]
            probes.extend(
                DestinationProbe(
                    jump.logical_id,
                    host.logical_id,
                    role,
                    host.private_address,
                    checks[role],
                )
                for host in role_hosts
            )
    ordered = tuple(
        sorted(
            probes,
            key=lambda item: (
                item.jump_host_id,
                item.target_logical_id,
                item.role,
                item.port,
            ),
        )
    )
    if len(ordered) > _MAX_DESTINATION_PROBES:
        raise ConfigurationError(
            f"destination probe selection exceeds {_MAX_DESTINATION_PROBES} pairs"
        )
    return ordered


def _is_rfc1918(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and any(
        address in ipaddress.ip_network(network)
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )


def _report(
    state: JumpHostState,
    readiness: ReadinessReport | None,
    connectivity: ConnectivityEvidence | None,
    *,
    generated_at: str,
    preflight: str = "passed",
    connectivity_failure: str | None = None,
) -> JumpHostCheckReport:
    statuses = (
        {item.logical_id: item.status.value for item in connectivity.hosts}
        if connectivity is not None
        else {}
    )
    probe_statuses = (
        {
            (
                item.jump_host_id,
                item.target_logical_id,
                item.role,
                item.port,
            ): item.status.value
            for item in connectivity.destination_probes
        }
        if connectivity is not None
        else {}
    )
    no_targets = not state.selected
    connectivity_status = (
        "not-performed-no-jump-hosts"
        if no_targets
        else connectivity_failure
        if connectivity_failure is not None
        else connectivity.status.value
        if connectivity is not None
        else "not-performed"
    )
    selected_probe_statuses = tuple(
        probe_statuses.get(
            (
                probe.jump_host_id,
                probe.target_logical_id,
                probe.role,
                probe.port,
            ),
            "not-performed",
        )
        for probe in state.probes
    )
    destination_status = _destination_status(
        selected_probe_statuses,
        requested=bool(state.probes),
        failure=connectivity_failure,
        preflight_passed=preflight == "passed",
    )
    checks = {
        "connectivity": connectivity_status,
        "destination_tcp": destination_status,
        "inventory_machine": (
            readiness.machine_status.value if readiness is not None else "not-performed"
        ),
        "inventory_preflight": (
            "not-performed-no-jump-hosts" if no_targets else preflight
        ),
        "route_validation": (
            readiness.route_status.value
            if readiness is not None
            else "locally-validated"
        ),
        "target_ssh": "not-performed",
    }
    failed = (
        preflight != "passed"
        or (
            connectivity is not None
            and connectivity.status is not ConnectivityStatus.SUCCESS
        )
        or connectivity_failure is not None
    )
    trust_entries = {entry.logical_id for entry in state.trust.record.entries}
    rows = tuple(
        JumpHostCheckRow(
            host.logical_id,
            host.zone,
            host.route_mode,
            "verified" if host.logical_id in trust_entries else "unavailable",
            statuses.get(
                host.logical_id,
                "not-performed" if not no_targets else "not-applicable",
            ),
        )
        for host in state.selected
    )
    probe_rows = tuple(
        DestinationProbeRow(
            probe.jump_host_id,
            probe.target_logical_id,
            probe.role,
            probe.port,
            "tcp",
            status,
        )
        for probe, status in zip(state.probes, selected_probe_statuses, strict=True)
    )
    return JumpHostCheckReport(
        generated_at,
        {
            "cluster_name": state.cluster.record.cluster_name,
            "cluster_uuid": str(state.cluster.record.cluster_uuid),
            "provider": state.cluster.record.provider,
        },
        {
            "count": len(state.selected),
            "depth": state.depth,
            "destinations": list(state.destinations),
            "stable_ids": [host.logical_id for host in state.selected],
        },
        {
            "inventory": {
                "digest": state.inventory.digest,
                "generation": state.inventory.record.generation,
                "status": "fresh",
            },
            "observation": {
                "digest": state.observed.record.manifest_digest,
                "generation": state.observed.record.generation,
                "status": "fresh",
            },
            "trust": {
                "digest": state.trust.digest,
                "generation": state.trust.record.generation,
                "status": "fresh",
            },
        },
        checks,
        rows,
        probe_rows,
        ExitCode.ANSIBLE if failed else ExitCode.SUCCESS,
    )


def render_check_jump_hosts_json(report: JumpHostCheckReport) -> str:
    return (
        json.dumps(
            report.to_object(),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def render_check_jump_hosts_human(report: JumpHostCheckReport) -> str:
    lines = [
        f"Cluster: {report.cluster['cluster_name']}",
        f"Jump hosts: {report.selection['count']}",
        f"Inventory preflight: {report.checks['inventory_preflight']}",
        f"Connectivity: {report.checks['connectivity']}",
        f"Destination TCP: {report.checks['destination_tcp']}",
    ]
    lines.extend(
        f"- {row.logical_id}: {row.connectivity} "
        f"(trust={row.trust}, route={row.route_mode}, zone={row.zone})"
        for row in report.jumps
    )
    lines.extend(
        f"- {row.jump_host_id} -> {row.target_logical_id}:{row.port}/"
        f"{row.protocol}: {row.status} (role={row.role})"
        for row in report.destination_probes
    )
    lines.append(f"Exit code: {int(report.exit_code)}")
    return "\n".join(lines) + "\n"


def _reject_unavailable_scope(request: OperationRequest) -> None:
    if _optional_string(request, "oci_auth_mode") is not None:
        raise ConfigurationError(
            "--oci-auth-mode is not used by the local jump-host check"
        )


def _sibling_executable(name: str) -> Path:
    candidate = Path(sys.executable).resolve().parent / name
    if not candidate.exists():
        raise ToolPrerequisiteError(
            f"required Ansible executable is unavailable beside Python: {name}"
        )
    return candidate.resolve(strict=True)


def _failure_kind(error: AnsibleError) -> str:
    if isinstance(error.__cause__, ProcessTimeoutError):
        return "timeout"
    message = str(error).lower()
    if any(term in message for term in ("evidence", "output", "recap")):
        return "invalid-evidence"
    return "failed"


def _strings(request: OperationRequest, name: str) -> tuple[str, ...]:
    value = request.option(name).value
    if not isinstance(value, tuple):
        raise ConfigurationError(f"--{name.replace('_', '-')} must be repeatable")
    return tuple(str(item) for item in value)


def _optional_string(request: OperationRequest, name: str) -> str | None:
    value = request.option(name).value
    return value if isinstance(value, str) else None


def _number(request: OperationRequest, name: str) -> float:
    value = request.option(name).value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"--{name.replace('_', '-')} must be numeric")
    return float(value)


def _integer_map(request: OperationRequest, name: str) -> dict[str, int]:
    value = request.option(name).value
    if not isinstance(value, tuple):
        raise ConfigurationError(f"--{name.replace('_', '-')} must be a mapping")
    result: dict[str, int] = {}
    for entry in value:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise ConfigurationError(
                f"--{name.replace('_', '-')} must contain KEY=VALUE entries"
            )
        key, item = entry
        if not isinstance(item, int) or isinstance(item, bool):
            raise ConfigurationError(
                f"--{name.replace('_', '-')} values must be integers"
            )
        result[key] = item
    return result


def _boolean(request: OperationRequest, name: str) -> bool:
    value = request.option(name).value
    if not isinstance(value, bool):
        raise ConfigurationError(f"--{name.replace('_', '-')} must be boolean")
    return value


def _destination_status(
    statuses: tuple[str, ...],
    *,
    requested: bool,
    failure: str | None,
    preflight_passed: bool,
) -> str:
    if not requested:
        return "not-performed"
    if not preflight_passed:
        return "not-performed"
    if failure is not None:
        return failure
    passed = sum(status == DestinationProbeStatus.PASSED.value for status in statuses)
    if passed == len(statuses):
        return "success"
    if passed:
        return "partial-failure"
    return "failure"


def _utc_now() -> datetime:
    return datetime.now(UTC)
