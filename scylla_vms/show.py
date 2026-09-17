"""Typed projection and deterministic rendering for local-only show reports."""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TextIO, cast

from scylla_vms.desired import (
    BlockVolumePolicy,
    ClusterSpec,
    HostRole,
    ServiceSpec,
    StoragePolicy,
)
from scylla_vms.errors import (
    ConfigurationError,
    ExitCode,
    OperationNotImplementedError,
)
from scylla_vms.journal import JournalStatus
from scylla_vms.locking import ClusterReadLock
from scylla_vms.models import OperationRequest
from scylla_vms.persistence import format_timestamp
from scylla_vms.reconciliation import ReconciliationClass
from scylla_vms.show_state import LocalShowState, load_local_show_state

SHOW_SCHEMA_VERSION = "deploy-scylla-vms.show/v1"
SHOW_SECTIONS = (
    "summary",
    "topology",
    "hosts",
    "storage",
    "services",
    "freshness",
    "readiness",
    "operations",
    "drift",
    "health",
)


@dataclass(frozen=True, slots=True)
class ShowFinding:
    """One allowlisted report finding used by post-render exit evaluation."""

    finding_class: str
    code: str
    source: str
    detail: str

    def to_object(self) -> dict[str, str]:
        return {
            "class": self.finding_class,
            "code": self.code,
            "detail": self.detail,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class ShowReport:
    """Stable public report envelope independent of persistence schemas."""

    generated_at: str
    selected_sections: tuple[str, ...]
    cluster: Mapping[str, object]
    sources: Mapping[str, object]
    sections: Mapping[str, object]
    findings: tuple[ShowFinding, ...]
    fail_on: tuple[str, ...]
    exit_code: ExitCode

    def to_object(self) -> dict[str, object]:
        return {
            "cluster": dict(self.cluster),
            "exit_status": {
                "code": int(self.exit_code),
                "fail_on": list(self.fail_on),
                "triggered_by": sorted(
                    {
                        finding.finding_class
                        for finding in self.findings
                        if finding.finding_class in self.fail_on
                    }
                ),
            },
            "findings": [finding.to_object() for finding in self.findings],
            "generated_at": self.generated_at,
            "schema_version": SHOW_SCHEMA_VERSION,
            "sections": dict(self.sections),
            "selected_sections": list(self.selected_sections),
            "sources": dict(self.sources),
        }


def run_show(
    request: OperationRequest,
    output: TextIO,
    *,
    clock: Callable[[], datetime] | None = None,
) -> int:
    """Load, project, and render the local report before evaluating findings."""

    if request.operation.name != "show":
        raise ConfigurationError("show runner requires a show request")
    lives = _strings(request, "live")
    if lives:
        requested = ", ".join(lives)
        raise OperationNotImplementedError(
            f"show live source(s) are not implemented: {requested}; no external "
            "checks were performed"
        )
    with ClusterReadLock(
        request.paths, _number(request, "lock_timeout_seconds")
    ) as lock:
        state = load_local_show_state(request, lock)
        report = build_show_report(
            request,
            state,
            generated_at=format_timestamp((clock or _utc_now)()),
        )
        rendered = (
            render_show_json(report)
            if _boolean(request, "json")
            else render_show_human(report)
        )
        output.write(rendered)
    return int(report.exit_code)


def build_show_report(
    request: OperationRequest,
    state: LocalShowState,
    *,
    generated_at: str,
) -> ShowReport:
    """Build a redacted allowlist projection from validated local state."""

    selected_sections = _selected_sections(_strings(request, "section"))
    selected_ids = _selected_node_ids(request, state.cluster.record.desired_spec)
    include_addresses = _boolean(request, "include_addresses")
    spec = state.cluster.record.desired_spec
    all_hosts = _host_rows(spec)
    hosts = tuple(row for row in all_hosts if row["logical_id"] in selected_ids)
    findings = _findings(state)
    fail_on = _strings(request, "fail_on")
    exit_code = _finding_exit(findings, fail_on)
    sources = _source_projection(state)
    available_sections: dict[str, object] = {
        "summary": _summary_section(state, len(all_hosts), len(hosts)),
        "topology": _topology_section(spec, selected_ids, state),
        "hosts": {
            "addresses": _address_section(state, selected_ids, include_addresses),
            "items": list(hosts),
            "observed_items": _observed_host_rows(state, selected_ids),
            "status": "reconciled" if state.observed is not None else "desired-only",
        },
        "storage": _storage_section(spec, selected_ids, state),
        "services": _services_section(spec, selected_ids, state),
        "freshness": {"sources": sources},
        "readiness": state.readiness.to_public_object(),
        "operations": _operations_section(state),
        "drift": {
            "conflicts": [
                {
                    "class": finding.finding_class.value,
                    "code": finding.code,
                    "field": finding.field,
                    "logical_id": finding.logical_id,
                }
                for finding in state.reconciliation.findings
                if finding.finding_class is not ReconciliationClass.MATCH
            ],
            "observed_state": (
                "persisted-local" if state.observed is not None else "unavailable"
            ),
            "status": state.reconciliation.status.value,
        },
        "health": {
            "connectivity": "not-performed",
            "manager": "unknown",
            "monitoring": "unknown",
            "scylla_ring": "unknown",
            "status": "unknown",
        },
    }
    sections = {
        name: available_sections[name]
        for name in SHOW_SECTIONS
        if name in selected_sections
    }
    metadata = state.cluster.record
    cluster = {
        "created_at": metadata.created_at,
        "desired_spec_digest": spec.digest(),
        "generation": metadata.generation,
        "metadata_digest": state.cluster.digest,
        "metadata_schema_version": metadata.schema_version,
        "name": metadata.cluster_name,
        "provider": metadata.provider,
        "provenance": {
            "request_digest": metadata.provenance.request_digest,
            "source": metadata.provenance.source.value,
        },
        "updated_at": metadata.updated_at,
        "uuid": str(metadata.cluster_uuid),
    }
    return ShowReport(
        generated_at,
        selected_sections,
        cluster,
        sources,
        sections,
        findings,
        fail_on,
        exit_code,
    )


def render_show_json(report: ShowReport) -> str:
    """Render one canonical JSON object with a trailing newline."""

    return (
        json.dumps(
            report.to_object(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def render_show_human(report: ShowReport) -> str:
    """Render a deterministic plain-text report from the public projection."""

    value = report.to_object()
    cluster = cast(dict[str, object], value["cluster"])
    lines = [
        f"Cluster report ({SHOW_SCHEMA_VERSION})",
        f"Generated: {report.generated_at}",
        f"Cluster: {cluster['name']} ({cluster['uuid']})",
        f"Provider: {cluster['provider']}",
        f"Metadata: generation {cluster['generation']}, {cluster['metadata_digest']}",
        "Selected sections: " + ", ".join(report.selected_sections),
        "",
        "Sources:",
    ]
    lines.extend(_human_lines(value["sources"], indent=2))
    for name in report.selected_sections:
        lines.extend(("", f"{name.upper()}:"))
        lines.extend(_human_lines(report.sections[name], indent=2))
    lines.extend(("", "Findings:"))
    if report.findings:
        for finding in report.findings:
            lines.append(
                f"  - {finding.finding_class}/{finding.code}: {finding.detail}"
            )
    else:
        lines.append("  none")
    lines.extend(
        (
            "",
            f"Exit status: {int(report.exit_code)} "
            f"(fail-on: {', '.join(report.fail_on)})",
        )
    )
    return "\n".join(lines) + "\n"


def _source_projection(state: LocalShowState) -> dict[str, object]:
    sources: dict[str, object] = {
        "connectivity": {
            "detail": "live connectivity was not requested",
            "status": "not-performed",
        },
        "desired": {
            "detail": (
                "validated during this local read; no infrastructure freshness implied"
            ),
            "digest": state.cluster.record.desired_spec.digest(),
            "status": "fresh",
            "timestamp": state.cluster.record.updated_at,
        },
        "health": {
            "detail": "live health was not requested",
            "status": "not-performed",
        },
        "metadata": {
            "detail": (
                "validated during this local read; no infrastructure freshness implied"
            ),
            "digest": state.cluster.digest,
            "status": "fresh",
            "timestamp": state.cluster.record.updated_at,
        },
        "provider": {
            "detail": "provider reads were not requested",
            "status": "not-performed",
        },
    }
    if state.observed is None:
        sources["terraform"] = {
            "detail": "no persisted Terraform observation is available",
            "status": "unavailable",
        }
    else:
        sources["terraform"] = {
            "detail": "persisted Terraform output validated locally; provider not queried",
            "digest": state.observed.record.manifest_digest,
            "generation": state.observed.record.generation,
            "status": "fresh",
            "timestamp": state.observed.record.captured_at,
        }
    if state.inventory is None:
        sources["inventory"] = {
            "detail": "no persisted inventory is available",
            "status": "unavailable",
        }
    else:
        inventory_fresh = (
            state.observed is not None
            and state.inventory.record.source_manifest_generation
            == state.observed.record.generation
            and state.inventory.record.source_manifest_digest
            == state.observed.record.manifest_digest
        )
        sources["inventory"] = {
            "detail": (
                "inventory is bound to the persisted manifest"
                if inventory_fresh
                else "inventory is not bound to the current persisted manifest"
            ),
            "digest": state.inventory.digest,
            "generation": state.inventory.record.generation,
            "status": "fresh" if inventory_fresh else "stale",
            "timestamp": state.inventory.record.captured_at,
        }
    if state.trust is None:
        sources["ssh_trust"] = {
            "detail": "no persisted SSH trust record is available",
            "status": "unavailable",
        }
    else:
        sources["ssh_trust"] = {
            "detail": "host fingerprints validated from protected local trust metadata",
            "digest": state.trust.digest,
            "generation": state.trust.record.generation,
            "status": (
                "fresh"
                if state.readiness.trust_status.value == "complete"
                else "stale"
                if state.readiness.trust_status.value == "changed"
                else "unknown"
            ),
            "timestamp": state.trust.record.confirmed_at,
        }
    if state.latest_operation is None:
        sources["operations"] = {
            "detail": "no persisted operation journal is available",
            "status": "unavailable",
        }
    else:
        sources["operations"] = {
            "detail": "journal validated locally; checkpoint evidence was not rerun",
            "digest": state.latest_operation.digest,
            "status": "fresh",
            "timestamp": state.latest_operation.record.updated_at,
        }
    return sources


def _summary_section(
    state: LocalShowState, total_hosts: int, selected_hosts: int
) -> dict[str, object]:
    spec = state.cluster.record.desired_spec
    return {
        "cluster_name": spec.cluster_name,
        "cluster_uuid": str(spec.cluster_uuid),
        "desired_host_count": total_hosts,
        "desired_provenance": {name: source.value for name, source in spec.provenance},
        "image_filters": {
            role.value: image_filter.to_object()
            for role, image_filter in spec.image_filters
        },
        "network": {
            "mode": spec.network.mode.value,
            "operator_cidrs": list(spec.network.operator_cidrs),
            "private_subnet_cidrs": dict(spec.network.private_subnet_cidrs),
            "public_endpoints": spec.network.public_endpoints,
            "public_subnet_cidrs": dict(spec.network.public_subnet_cidrs),
            "ssh_public_key_configured": True,
            "ssh_user": spec.network.ssh_user,
            "subnets": {
                role.value: subnet_id for role, subnet_id in spec.network.subnets
            },
            "vcn_cidr": spec.network.vcn_cidr,
            "vcn_id": spec.network.vcn_id,
        },
        "oci_compartment_id": spec.oci_compartment_id,
        "oci_region": spec.oci_region,
        "observed_host_count": (
            len(state.observed.record.manifest.hosts) if state.observed else None
        ),
        "provider": spec.provider,
        "scylla_datacenter": {
            "source": spec.scylla_datacenter.source,
            "value": spec.scylla_datacenter.value,
        },
        "selected_host_count": selected_hosts,
        "status": "reconciled" if state.observed is not None else "desired-only",
    }


def _topology_section(
    spec: ClusterSpec, selected_ids: frozenset[str], state: LocalShowState
) -> dict[str, object]:
    return {
        "scylla_datacenter": {
            "source": spec.scylla_datacenter.source,
            "value": spec.scylla_datacenter.value,
        },
        "observed": [
            {
                "logical_id": host.logical_id,
                "scylla_datacenter": host.scylla_datacenter,
                "scylla_rack": host.scylla_rack,
                "zone_id": host.zone,
            }
            for host in (state.observed.record.manifest.hosts if state.observed else ())
            if host.logical_id in selected_ids
        ],
        "status": "reconciled" if state.observed is not None else "desired-only",
        "zones": [
            {
                "logical_node_ids": [
                    logical_id
                    for logical_id in zone.logical_node_ids
                    if logical_id in selected_ids
                ],
                "rack": {
                    "source": zone.scylla_rack.source,
                    "value": zone.scylla_rack.value,
                },
                "scylla_nodes": zone.scylla_nodes,
                "zone_id": zone.zone_id,
            }
            for zone in spec.zones
        ],
    }


def _host_rows(spec: ClusterSpec) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    for zone in spec.zones:
        rows.extend(
            {
                "instance_type": spec.scylla_instance_type,
                "logical_id": logical_id,
                "rack": zone.scylla_rack.value,
                "role": HostRole.SCYLLA.value,
                "zone_id": zone.zone_id,
            }
            for logical_id in zone.logical_node_ids
        )
    for service in spec.services:
        rows.extend(
            {
                "instance_type": service.instance_type,
                "logical_id": logical_id,
                "rack": None,
                "role": service.role.value,
                "zone_id": service.zones[index],
            }
            for index, logical_id in enumerate(service.logical_ids)
        )
    return tuple(sorted(rows, key=lambda row: cast(str, row["logical_id"])))


def _observed_host_rows(
    state: LocalShowState, selected_ids: frozenset[str]
) -> list[dict[str, object]]:
    if state.observed is None:
        return []
    return [
        {
            "jump_host_id": host.jump_host_id,
            "logical_id": host.logical_id,
            "provider_id": host.provider_id,
            "role": host.role.value,
            "shape": host.shape,
            "zone_id": host.zone,
        }
        for host in state.observed.record.manifest.hosts
        if host.logical_id in selected_ids
    ]


def _address_section(
    state: LocalShowState,
    selected_ids: frozenset[str],
    include_addresses: bool,
) -> dict[str, object]:
    if state.observed is None and state.inventory is None:
        return {
            "items": [],
            "requested": include_addresses,
            "status": "unavailable",
        }
    if not include_addresses:
        return {"items": [], "requested": False, "status": "redacted"}
    if state.observed is None:
        assert state.inventory is not None
        return {
            "items": [
                {
                    "logical_id": host.logical_id,
                    "private": host.private_address,
                    "public": host.public_address,
                    "source": "persisted-inventory",
                }
                for host in state.inventory.record.inventory.hosts
                if host.logical_id in selected_ids
            ],
            "requested": True,
            "status": "stale",
        }
    return {
        "items": [
            {
                "logical_id": host.logical_id,
                "private": host.private_address,
                "public": host.public_address,
                "source": "persisted-terraform-observation",
            }
            for host in state.observed.record.manifest.hosts
            if host.logical_id in selected_ids
        ],
        "requested": True,
        "status": "available",
    }


def _storage_section(
    spec: ClusterSpec, selected_ids: frozenset[str], state: LocalShowState
) -> dict[str, object]:
    host_roles = {
        cast(str, row["logical_id"]): cast(str, row["role"]) for row in _host_rows(spec)
    }
    show_all_roles = selected_ids == frozenset(host_roles)
    selected_roles = {
        role for logical_id, role in host_roles.items() if logical_id in selected_ids
    }
    return {
        "policies": [
            _storage_policy(policy, selected_ids, host_roles)
            for policy in spec.storage
            if show_all_roles or policy.role.value in selected_roles
        ],
        "observed": [
            {
                "device_count": host.storage.expected_device_count,
                "ephemeral": bool(host.storage.devices)
                and all(device.ephemeral for device in host.storage.devices),
                "logical_id": host.logical_id,
                "raw_gib": host.storage.raw_total_gib,
                "selected_backend": host.storage.selected_backend.value,
                "storage_generation": host.storage.storage_generation,
                "usable_gib": host.storage.usable_total_gib,
            }
            for host in (state.observed.record.manifest.hosts if state.observed else ())
            if host.logical_id in selected_ids
        ],
        "status": "reconciled" if state.observed is not None else "desired-only",
    }


def _storage_policy(
    policy: StoragePolicy,
    selected_ids: frozenset[str],
    host_roles: Mapping[str, str],
) -> dict[str, object]:
    return {
        "block_volume": _block_volume(policy.block_volume),
        "host_ids": sorted(
            logical_id
            for logical_id, role in host_roles.items()
            if role == policy.role.value and logical_id in selected_ids
        ),
        "layout": policy.layout.value if policy.layout is not None else None,
        "local_min_device_count": policy.local_min_device_count,
        "local_min_total_gib": policy.local_min_total_gib,
        "requested_backend": policy.requested_backend.value,
        "role": policy.role.value,
    }


def _block_volume(policy: BlockVolumePolicy | None) -> dict[str, object] | None:
    if policy is None:
        return None
    return {
        "attachment_type": policy.attachment_type.value,
        "chap_enabled": policy.chap_enabled,
        "count": policy.count,
        "customer_key_configured": policy.key_id is not None,
        "in_transit_encryption": policy.in_transit_encryption,
        "retention": policy.retention.value,
        "size_gib": policy.size_gib,
        "vpus_per_gb": policy.vpus_per_gb,
    }


def _services_section(
    spec: ClusterSpec, selected_ids: frozenset[str], state: LocalShowState
) -> dict[str, object]:
    return {
        "items": [
            _service(service, selected_ids)
            for service in spec.services
            if any(logical_id in selected_ids for logical_id in service.logical_ids)
        ],
        "observed_counts": {
            role.value: sum(
                host.role is role
                for host in (
                    state.observed.record.manifest.hosts if state.observed else ()
                )
            )
            for role in (HostRole.MANAGER, HostRole.MONITORING, HostRole.JUMP_HOST)
        },
        "status": "reconciled" if state.observed is not None else "desired-only",
    }


def _service(service: ServiceSpec, selected_ids: frozenset[str]) -> dict[str, object]:
    selected = [
        (logical_id, service.zones[index])
        for index, logical_id in enumerate(service.logical_ids)
        if logical_id in selected_ids
    ]
    return {
        "count": service.count,
        "hosts": [
            {"logical_id": logical_id, "zone_id": zone} for logical_id, zone in selected
        ],
        "instance_type": service.instance_type,
        "role": service.role.value,
    }


def _operations_section(state: LocalShowState) -> dict[str, object]:
    if state.latest_operation is None:
        return {"latest": None, "status": "unavailable"}
    record = state.latest_operation.record
    return {
        "latest": {
            "checkpoint_evidence": [
                {
                    "phase": evidence.phase.value,
                    "result": evidence.result.value,
                    "summary_code": evidence.summary_code,
                }
                for evidence in record.evidence
            ],
            "digest": state.latest_operation.digest,
            "generation": record.generation,
            "operation": record.operation,
            "operation_id": str(record.operation_id),
            "phase": record.phase.value,
            "status": record.status.value,
            "updated_at": record.updated_at,
        },
        "status": "fresh",
    }


def _findings(state: LocalShowState) -> tuple[ShowFinding, ...]:
    findings = [
        ShowFinding(
            "unknown",
            "provider-not-performed",
            "provider",
            "provider validation was not performed",
        ),
        ShowFinding(
            "unknown",
            "connectivity-not-performed",
            "connectivity",
            "connectivity validation was not performed",
        ),
        ShowFinding(
            "unknown",
            "health-not-performed",
            "health",
            "live health validation was not performed",
        ),
    ]
    if state.observed is None:
        findings.append(
            ShowFinding(
                "unknown",
                "terraform-observation-unavailable",
                "terraform",
                "Terraform-observed state is unavailable",
            )
        )
    for finding in state.reconciliation.findings:
        if finding.finding_class is ReconciliationClass.MATCH:
            continue
        finding_class = {
            ReconciliationClass.INTENDED_CHANGE: "drift",
            ReconciliationClass.DRIFT: "drift",
            ReconciliationClass.UNKNOWN: "unknown",
            ReconciliationClass.SENSITIVE_CONFLICT: "conflict",
        }[finding.finding_class]
        findings.append(
            ShowFinding(
                finding_class,
                finding.code,
                "reconciliation",
                (
                    f"local reconciliation finding for {finding.logical_id}"
                    if finding.logical_id is not None
                    else "local reconciliation finding"
                ),
            )
        )
    if state.inventory is None:
        findings.append(
            ShowFinding(
                "unknown",
                "inventory-unavailable",
                "inventory",
                "validated inventory is unavailable",
            )
        )
    else:
        inventory_fresh = (
            state.observed is not None
            and state.inventory.record.source_manifest_generation
            == state.observed.record.generation
            and state.inventory.record.source_manifest_digest
            == state.observed.record.manifest_digest
        )
        if not inventory_fresh:
            findings.append(
                ShowFinding(
                    "stale",
                    "inventory-stale",
                    "inventory",
                    "persisted inventory is not bound to the current manifest",
                )
            )
    if state.readiness.trust_status.value != "complete":
        trust_class = (
            "conflict" if state.readiness.trust_status.value == "changed" else "unknown"
        )
        findings.append(
            ShowFinding(
                trust_class,
                "host-trust-" + state.readiness.trust_status.value,
                "ssh-trust",
                "SSH host trust is not ready for production execution",
            )
        )
    if state.latest_operation is None:
        findings.append(
            ShowFinding(
                "unknown",
                "operation-journal-unavailable",
                "operations",
                "no validated operation journal is available",
            )
        )
    elif state.latest_operation.record.status in {
        JournalStatus.PENDING,
        JournalStatus.IN_PROGRESS,
        JournalStatus.INTERRUPTED,
        JournalStatus.FAILED,
    }:
        findings.append(
            ShowFinding(
                "conflict",
                "incomplete-operation",
                "operations",
                "the latest persisted operation is not successfully complete",
            )
        )
    return tuple(sorted(findings, key=lambda item: (item.finding_class, item.code)))


def _finding_exit(
    findings: tuple[ShowFinding, ...], fail_on: tuple[str, ...]
) -> ExitCode:
    if fail_on == ("none",):
        return ExitCode.SUCCESS
    triggered = {
        finding.finding_class
        for finding in findings
        if finding.finding_class in fail_on
    }
    if triggered & {"stale", "drift", "conflict", "unknown"}:
        return ExitCode.DRIFT_CONFLICT
    if "unhealthy" in triggered:
        return ExitCode.HEALTH
    return ExitCode.SUCCESS


def _selected_sections(configured: tuple[str, ...]) -> tuple[str, ...]:
    if configured == ("all",):
        return SHOW_SECTIONS
    return tuple(section for section in SHOW_SECTIONS if section in configured)


def _selected_node_ids(request: OperationRequest, spec: ClusterSpec) -> frozenset[str]:
    all_ids = frozenset(
        logical_id for zone in spec.zones for logical_id in zone.logical_node_ids
    ) | frozenset(
        logical_id for service in spec.services for logical_id in service.logical_ids
    )
    configured = frozenset(_strings(request, "node_id"))
    unknown = sorted(configured - all_ids)
    if unknown:
        raise ConfigurationError("unknown --node-id: " + ", ".join(unknown))
    return configured or all_ids


def _strings(request: OperationRequest, name: str) -> tuple[str, ...]:
    value = request.option(name).value
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"{name} did not resolve to a string list")
    return cast(tuple[str, ...], value)


def _boolean(request: OperationRequest, name: str) -> bool:
    value = request.option(name).value
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} did not resolve to a boolean")
    return value


def _number(request: OperationRequest, name: str) -> float:
    value = request.option(name).value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{name} did not resolve to a number")
    return float(value)


def _human_lines(value: object, *, indent: int) -> list[str]:
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key in sorted(value):
            child = value[key]
            if isinstance(child, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_human_lines(child, indent=indent + 2))
            else:
                lines.append(f"{prefix}{key}: {_human_scalar(child)}")
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{prefix}(empty)"]
        lines = []
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{prefix}-")
                lines.extend(_human_lines(child, indent=indent + 2))
            else:
                lines.append(f"{prefix}- {_human_scalar(child)}")
        return lines
    return [f"{prefix}{_human_scalar(value)}"]


def _human_scalar(value: object) -> str:
    if value is None:
        return "unavailable"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _utc_now() -> datetime:
    return datetime.now(UTC)
