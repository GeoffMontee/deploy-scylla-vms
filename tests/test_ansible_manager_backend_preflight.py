import base64
import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import FakeRunner, _builder
from test_ansible_deploy_manager_backend_configuration_plan import (
    _call as _plan_backend,
)
from test_ansible_deploy_manager_backend_configuration_plan import (
    _prepared as _prepare_backend,
)
from test_ansible_deploy_manager_backend_configuration_plan import (
    _records as _backend_records,
)
from test_provider_source import CLUSTER_UUID

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.manager_backend_preflight import (
    MANAGER_BACKEND_NOT_PERFORMED,
    MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION,
    MANAGER_BACKEND_UNRESOLVED_BLOCKERS,
    ManagerBackendLoopbackStatus,
    ManagerBackendPackageStatus,
    ManagerBackendPreflightStatus,
    ManagerBackendServiceStatus,
    build_manager_backend_preflight_payload,
    parse_manager_backend_preflight_execution,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    ManagerServerEvidence,
    ManagerServerStatus,
    build_manager_server_payload,
)
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import (
    PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import InventoryStore
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadataStore
from scylla_vms.process import ProcessResult

DIGEST = "sha256:" + "a" * 64


def _readiness(inventory: object, context: object) -> ReadinessReport:
    stored = cast(Any, inventory)
    record = cast(Any, context).record
    return ReadinessReport(
        EvidenceStatus.FRESH,
        EvidenceStatus.FRESH,
        TrustReadiness.COMPLETE,
        RouteReadiness.VALID,
        stored.record.source_manifest_generation,
        stored.record.source_manifest_digest,
        stored.record.generation,
        stored.digest,
        record.trust_generation,
        record.trust_artifact_digest,
        len(stored.record.inventory.hosts),
        len(stored.record.inventory.hosts),
        (),
        RouteReport(RouteReadiness.VALID, 1, 3, 1, ()),
        tuple((classification, ()) for classification in OperationClassification),
    )


def _base_os(logical_id: str) -> BaseOsEvidence:
    return BaseOsEvidence(
        BaseOsStatus.NO_CHANGE,
        (
            BaseOsHostEvidence(
                logical_id,
                BaseOsStatus.NO_CHANGE,
                False,
                False,
                "already-current",
            ),
        ),
    )


def _manager_server(
    logical_id: str,
    provenance: dict[str, object],
) -> ManagerServerEvidence:
    return ManagerServerEvidence(
        logical_id,
        ManagerServerStatus.NO_CHANGE,
        MANAGER_RELEASE_LINE,
        MANAGER_PACKAGE_VERSION,
        MANAGER_PACKAGE_VERSION,
        tuple((name, MANAGER_PACKAGE_VERSION) for name in MANAGER_PACKAGES),
        MANAGER_REPOSITORY_DEFINITION_DIGEST,
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        tuple(
            sorted((str(name), cast(str, value)) for name, value in provenance.items())
        ),
        (),
    )


def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, _ = _prepare_backend(tmp_path, monkeypatch)
    _plan_backend(prepared)
    backend_context, backend_plan = _backend_records(prepared)
    metadata = ClusterMetadataStore(prepared.paths).read(
        expected_cluster_name="example",
        expected_cluster_uuid=CLUSTER_UUID,
        expected_provider="oci",
    )
    observed = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    inventory = InventoryStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    logical_id = backend_context.record.manager_target_id
    readiness = _readiness(inventory, backend_context)
    base_os = _base_os(logical_id)
    manager_server_payload = build_manager_server_payload(
        metadata.record,
        observed,
        inventory,
        readiness,
        base_os,
        logical_id=logical_id,
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        package_version=MANAGER_PACKAGE_VERSION,
        cluster_spec_digest=backend_context.record.desired_spec_digest,
    )
    manager_server = _manager_server(
        logical_id,
        cast(dict[str, object], manager_server_payload["provenance"]),
    )
    payload = build_manager_backend_preflight_payload(
        metadata.record,
        observed,
        inventory,
        readiness,
        base_os,
        manager_server,
        backend_context,
        backend_plan,
        logical_id=logical_id,
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
    )
    return (
        prepared,
        payload,
        metadata.record,
        observed,
        inventory,
        readiness,
        base_os,
        manager_server,
        backend_context,
        backend_plan,
    )


def _result(payload: dict[str, object]) -> dict[str, object]:
    path = (
        Path(__file__).parent / "fixtures/ansible/manager-backend-preflight-result.json"
    )
    result = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    result["logical_id"] = payload["logical_id"]
    result["provenance"] = payload["provenance"]
    return result


def _stdout(payload: dict[str, object], result: dict[str, object] | None = None) -> str:
    value = result or _result(payload)
    encoded = base64.b64encode(
        json.dumps(value, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    return (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MANAGER_BACKEND_PREFLIGHT_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=4 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )


def test_payload_adopts_exact_local_policy_and_refuses_stale_prerequisites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        _prepared,
        payload,
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        manager_server,
        backend_context,
        backend_plan,
    ) = _context(tmp_path, monkeypatch)
    policy = cast(dict[str, object], payload["backend_policy"])
    assert payload["schema_version"] == MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION
    assert policy["backend_mode"] == "local-one-node"
    assert policy["target_role"] == "manager"
    assert policy["managed_data_cluster_backend"] == "forbidden"
    assert policy["cql_network_ingress"] == "forbidden"
    assert policy["contact_scope"] == "loopback-only"
    assert policy["cql_port"] == 9042
    assert policy["scylla_release"] == "2026.2"
    assert policy["backend_credentials"] == policy["backend_tls"] == "not-required"
    assert payload["not_performed"] == list(MANAGER_BACKEND_NOT_PERFORMED)
    assert payload["unresolved_blockers"] == list(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
    encoded = json.dumps(payload, sort_keys=True)
    for protected in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "password",
        "credential_value",
        "private_key",
    ):
        assert protected not in encoded

    with pytest.raises(StateConflictError, match=r"Ubuntu 24\.04"):
        build_manager_backend_preflight_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            manager_server,
            backend_context,
            backend_plan,
            logical_id=cast(str, payload["logical_id"]),
            image_filter=ImageFilter("Ubuntu", "22.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="install-only"):
        build_manager_backend_preflight_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            replace(manager_server, service_inactive=False),
            backend_context,
            backend_plan,
            logical_id=cast(str, payload["logical_id"]),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    stale_manager_server = replace(
        manager_server,
        provenance=tuple(
            (
                name,
                "sha256:" + "b" * 64 if name == "trust_digest" else digest,
            )
            for name, digest in manager_server.provenance
        ),
    )
    with pytest.raises(StateConflictError, match="evidence provenance"):
        build_manager_backend_preflight_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            stale_manager_server,
            backend_context,
            backend_plan,
            logical_id=cast(str, payload["logical_id"]),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="provenance"):
        build_manager_backend_preflight_payload(
            metadata,
            observed,
            inventory,
            replace(readiness, trust_digest="sha256:" + "b" * 64),
            base_os,
            manager_server,
            backend_context,
            backend_plan,
            logical_id=cast(str, payload["logical_id"]),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )


def test_parser_accepts_planning_evidence_but_never_operational_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _context(tmp_path, monkeypatch)[1]
    evidence = parse_manager_backend_preflight_execution(
        _stdout(payload),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is ManagerBackendPreflightStatus.EVIDENCE_READY
    assert evidence.manager_package_status is ManagerBackendPackageStatus.INSTALLED
    assert (
        evidence.local_scylla_package_status
        is ManagerBackendPackageStatus.NOT_INSTALLED
    )
    assert (
        evidence.manager_service_status is ManagerBackendServiceStatus.MASKED_INACTIVE
    )
    assert evidence.local_scylla_service_status is ManagerBackendServiceStatus.ABSENT
    assert evidence.loopback_policy_status is ManagerBackendLoopbackStatus.AVAILABLE
    assert evidence.operational_readiness == "not-performed"
    assert set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS) <= set(evidence.blockers)

    changed = _result(payload)
    changed["provenance"] = {
        **cast(dict[str, str], payload["provenance"]),
        "inventory_digest": "sha256:" + "b" * 64,
    }
    with pytest.raises(AnsibleError, match="provenance"):
        parse_manager_backend_preflight_execution(
            _stdout(payload, changed),
            expected_payload=payload,
            exit_code=0,
        )

    protected = _result(payload)
    protected["password"] = "obviously-fake-secret"
    with pytest.raises(AnsibleError, match="schema") as caught:
        parse_manager_backend_preflight_execution(
            _stdout(payload, protected),
            expected_payload=payload,
            exit_code=0,
        )
    assert "obviously-fake-secret" not in str(caught.value)

    marker = _stdout(payload).partition("PLAY RECAP")[0]
    with pytest.raises(AnsibleError, match="duplicated"):
        parse_manager_backend_preflight_execution(
            marker + _stdout(payload),
            expected_payload=payload,
            exit_code=0,
        )


def test_registry_source_and_service_check_mode_are_strict_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        prepared,
        payload,
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        manager_server,
        backend_context,
        backend_plan,
    ) = _context(tmp_path, monkeypatch)
    definition = get_playbook("manager-backend-preflight")
    assert definition.source_available
    assert definition.hosts == "manager"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.SUPPORTED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.READ_ONLY
    assert definition.pre_health_gate
    assert len(PLAYBOOKS) == 36

    expected_paths = {
        "playbooks/manager-backend-preflight.yml",
        "playbooks/roles/manager_backend_preflight/tasks/main.yml",
        "playbooks/roles/manager_backend_preflight/library/manager_backend_preflight.py",
        "playbooks/roles/manager_backend_preflight/files/manager-backend-preflight.provenance.yml",
    }
    assert expected_paths <= {item.path for item in load_ansible_source_bundle().files}

    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _stdout(payload), "obviously-fake-secret"),
        ]
    )
    service = AnsibleService(_builder(tmp_path, prepared.paths), runner)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_manager_backend_preflight(
            lock,
            metadata,
            observed,
            inventory,
            base_os,
            manager_server,
            backend_context,
            backend_plan,
            limit=(cast(str, payload["logical_id"]),),
            readiness=readiness,
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            check=True,
        )
    assert result.check_mode
    assert result.stdout == result.stderr == ""
    assert result.manager_backend_preflight is not None
    assert (
        result.manager_backend_preflight.status
        is ManagerBackendPreflightStatus.EVIDENCE_READY
    )
    assert runner.runtime_payloads
    runtime = json.dumps(runner.runtime_payloads, sort_keys=True)
    assert "obviously-fake-secret" not in runtime
    assert "10.0." not in runtime
    assert "ocid1." not in runtime


def test_remote_module_is_bounded_check_mode_safe_and_refuses_unsafe_host_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _remote_module()
    payload = {
        "architecture": "amd64",
        "backend_policy": {
            "backend_mode": "local-one-node",
            "target_role": "manager",
            "managed_data_cluster_backend": "forbidden",
            "cql_network_ingress": "forbidden",
            "contact_scope": "loopback-only",
            "cql_port": 9042,
            "scylla_release": "2026.2",
            "backend_credentials": "not-required",
            "backend_tls": "not-required",
            "configuration_write": "not-performed",
            "local_scylla_service_start": "not-performed",
            "manager_agent_token_policy": "environment-only-required",
            "manager_service_start": "not-performed",
            "manager_service_state": "masked-inactive",
            "package_installation": "not-performed",
            "policy_digest": DIGEST,
            "schema_creation": "not-performed",
            "schema_version": (
                "deploy-scylla-vms.manager-backend-local-one-node-policy/v1"
            ),
            "setup_execution": "not-performed",
        },
        "cluster_uuid": str(CLUSTER_UUID),
        "expected_manager_package_version": MANAGER_PACKAGE_VERSION,
        "guest_architecture": "x86_64",
        "local_scylla_packages": ["scylla", "scylla-server"],
        "local_scylla_service": "scylla-server.service",
        "logical_id": "manager-1",
        "manager_packages": list(MANAGER_PACKAGES),
        "manager_service": "scylla-manager.service",
        "not_performed": list(MANAGER_BACKEND_NOT_PERFORMED),
        "operating_system": "Ubuntu",
        "operating_system_version": "24.04",
        "provenance": {"source_digest": DIGEST},
        "role": "manager",
        "schema_version": MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION,
        "unresolved_blockers": list(MANAGER_BACKEND_UNRESOLVED_BLOCKERS),
    }
    monkeypatch.setattr(module, "_operating_system", lambda: ("Ubuntu", "24.04"))
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        module,
        "_capacity",
        lambda: {
            "approved_mount_count": 1,
            "available_mount_count": 1,
            "cpu_count": 4,
            "memory_bytes": 8 * 1024**3,
            "root_free_bytes": 50 * 1024**3,
            "root_total_bytes": 100 * 1024**3,
        },
    )
    monkeypatch.setattr(
        module,
        "_package_state",
        lambda packages, **_: (
            "installed" if packages == list(MANAGER_PACKAGES) else "not-installed"
        ),
    )
    monkeypatch.setattr(
        module,
        "_service_state",
        lambda unit, _: (
            "masked-inactive" if unit == "scylla-manager.service" else "absent"
        ),
    )
    monkeypatch.setattr(module, "_reboot_required", lambda: False)
    monkeypatch.setattr(module, "_loopback_status", lambda: "available")

    result = module._inspect(payload, 15)
    assert result["status"] == "evidence-ready"
    assert result["operational_readiness"] == "not-performed"
    assert result["not_performed"] == list(MANAGER_BACKEND_NOT_PERFORMED)
    assert result["blockers"] == list(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)

    monkeypatch.setattr(
        module,
        "_package_state",
        lambda packages, **_: "installed",
    )
    blocked = module._inspect(payload, 15)
    assert blocked["status"] == "blocked"
    assert "local-scylla-package-present" in blocked["blockers"]

    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "supports_check_mode=True" in source
    for forbidden in (
        "apt-cache",
        "apt-get",
        "curl",
        "metadata.oraclecloud",
        "subprocess.Popen",
        "shell=True",
        'systemctl", "start',
        'systemctl", "enable',
    ):
        assert forbidden not in source


def _remote_module() -> Any:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles"
        / "manager_backend_preflight/library/manager_backend_preflight.py"
    )
    spec = importlib.util.spec_from_file_location(
        "manager_backend_preflight_remote", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
