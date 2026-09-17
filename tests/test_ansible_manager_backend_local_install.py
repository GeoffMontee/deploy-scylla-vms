import base64
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_ansible import FakeRunner, _builder
from test_ansible_deploy_manager_backend_installation_plan import (
    _call as _plan_installation,
)
from test_ansible_deploy_manager_backend_installation_plan import (
    _records as _installation_records,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    ManagerBackendPreflightRunner,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _call as _execute_preflight,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _prepared as _prepare_preflight,
)
from test_ansible_deploy_manager_backend_preflight_reconciliation import (
    _call as _reconcile_preflight,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.manager_backend_local_install as install_module
from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    DeployManagerBackendPreflightExecutionStore,
    _load_execution_context,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    DeployManagerBackendPreflightReconciliationStore,
)
from scylla_vms.ansible.manager_backend_local_install import (
    MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS,
    MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION,
    MANAGER_BACKEND_LOCAL_INSTALL_SOURCE_PATHS,
    ManagerBackendLocalInstallStatus,
    build_manager_backend_local_install_payload,
    parse_manager_backend_local_install_execution,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

_FIXTURE = (
    Path(__file__).parent / "fixtures/ansible/manager-backend-local-install-result.json"
)


@pytest.fixture(scope="module")
def contract(tmp_path_factory: pytest.TempPathFactory):
    monkeypatch = pytest.MonkeyPatch()
    root = tmp_path_factory.mktemp("manager-backend-local-install")
    prepared, executables, toolchain = _prepare_preflight(root, monkeypatch)
    runner = ManagerBackendPreflightRunner()
    _execute_preflight(prepared, runner, executables, toolchain)
    _reconcile_preflight(prepared)
    _plan_installation(prepared)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployManagerBackendPreflightExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        binding = execution.record.binding
        current = _load_execution_context(
            prepared.paths,
            OPERATION_ID,
            lock=lock,
            toolchain_version=binding.toolchain_version,
            executable_identity_digest=binding.executable_identity_digest,
            toolchain_evidence_digest=binding.toolchain_evidence_digest,
        )
        reconciliation = DeployManagerBackendPreflightReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    installation_context, installation_plan = _installation_records(prepared)
    value = SimpleNamespace(
        prepared=prepared,
        current=current,
        reconciliation=reconciliation,
        installation_context=installation_context,
        installation_plan=installation_plan,
    )
    yield value
    monkeypatch.undo()


def _payload(contract: Any) -> dict[str, object]:
    current = contract.current
    return build_manager_backend_local_install_payload(
        current.metadata,
        current.observation,
        current.inventory,
        current.readiness,
        current.scope.base_os,
        current.scope.manager_server,
        contract.reconciliation,
        contract.installation_context,
        contract.installation_plan,
        logical_id="manager-1",
        image_filter=current.scope.image_filter,
        architecture=current.scope.architecture,
    )


def _result(
    payload: dict[str, object],
    status: str = "no-change",
) -> dict[str, object]:
    value = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    value["provenance"] = payload["provenance"]
    value["source_digest"] = payload["source_digest"]
    value["command_policy_digest"] = payload["command_policy_digest"]
    value["status"] = status
    value["changed"] = status == "installed"
    if status in {"not-predicted", "failed"}:
        value["installed_version"] = None
        value["packages"] = {}
        value["service_masked"] = None
        value["service_inactive"] = None
    value["blockers"] = ["execution-failed"] if status == "failed" else []
    return cast(dict[str, object], value)


def _stdout(
    payload: dict[str, object],
    status: str = "no-change",
    *,
    extra: str = "",
) -> tuple[str, int]:
    value = _result(payload, status)
    encoded = base64.b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    changed = 1 if status == "installed" else 0
    failed = 1 if status == "failed" else 0
    return (
        f"{extra}ok: [manager-1] => "
        f'{{"msg":"DSV_MANAGER_BACKEND_LOCAL_INSTALL_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"manager-1 : ok=14 changed={changed} unreachable=0 failed={failed} "
        "skipped=0 rescued=0 ignored=0\n",
        2 if failed else 0,
    )


def test_payload_is_exact_package_only_and_redacted(contract) -> None:
    payload = _payload(contract)
    assert payload["schema_version"] == MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION
    assert payload["logical_id"] == "manager-1"
    assert payload["role"] == "manager"
    assert payload["packages"] == list(SCYLLA_PACKAGES)
    assert payload["package_version"] == SCYLLA_PACKAGE_VERSION
    assert payload["repository"] == {
        "definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
        "uri": (
            "https://downloads.scylladb.com/downloads/scylla/deb/"
            "debian-ubuntu/scylladb-2026.2"
        ),
    }
    assert (
        cast(dict[str, object], payload["signing_key"])["artifact_digest"]
        == SCYLLA_SIGNING_KEY_DIGEST
    )
    provenance = cast(dict[str, str], payload["provenance"])
    assert set(provenance) == {
        "ansible_source_digest",
        "base_os_evidence_digest",
        "catalog_digest",
        "desired_spec_digest",
        "installation_context_artifact_digest",
        "installation_context_record_digest",
        "installation_plan_artifact_digest",
        "installation_plan_digest",
        "inventory_digest",
        "manager_server_evidence_digest",
        "manager_server_provenance_digest",
        "observation_digest",
        "package_reference_digest",
        "preflight_reconciliation_artifact_digest",
        "preflight_reconciliation_record_digest",
        "storage_decision_digest",
        "trust_digest",
    }
    encoded = json.dumps(payload, sort_keys=True)
    for protected in (
        "203.0.113.",
        "10.0.0.",
        "ocid1.",
        "provider_id",
        "auth_token",
        "credential",
        "password",
        "private_key",
    ):
        assert protected not in encoded


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("no-change", ManagerBackendLocalInstallStatus.NO_CHANGE),
        ("installed", ManagerBackendLocalInstallStatus.INSTALLED),
        ("not-predicted", ManagerBackendLocalInstallStatus.NOT_PREDICTED),
        ("failed", ManagerBackendLocalInstallStatus.FAILED),
    ],
)
def test_parser_accepts_only_strict_terminal_evidence(
    contract,
    status: str,
    expected: ManagerBackendLocalInstallStatus,
) -> None:
    payload = _payload(contract)
    stdout, exit_code = _stdout(payload, status)
    evidence = parse_manager_backend_local_install_execution(
        stdout,
        expected_payload=payload,
        exit_code=exit_code,
    )
    assert evidence.status is expected
    assert evidence.role == "manager"
    assert evidence.requested_version == SCYLLA_PACKAGE_VERSION
    assert all(
        getattr(evidence, name) is False
        for name in MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS
    )
    if expected in {
        ManagerBackendLocalInstallStatus.INSTALLED,
        ManagerBackendLocalInstallStatus.NO_CHANGE,
    }:
        assert evidence.packages == tuple(
            (name, SCYLLA_PACKAGE_VERSION) for name in SCYLLA_PACKAGES
        )
        assert evidence.service_masked is evidence.service_inactive is True


def test_parser_refuses_forbidden_actions_tamper_and_unbounded_output(contract) -> None:
    payload = _payload(contract)
    for mutation, match in (
        ({"service_started": True}, "forbidden action"),
        ({"repository_digest": "sha256:" + "0" * 64}, "source provenance"),
        ({"logical_id": "manager-2"}, "evidence conflicts"),
        ({"extra": False}, "schema is invalid"),
    ):
        value = _result(payload)
        value.update(mutation)
        encoded = base64.b64encode(json.dumps(value).encode()).decode()
        stdout = (
            f"DSV_MANAGER_BACKEND_LOCAL_INSTALL_B64={encoded}\n"
            "PLAY RECAP *****\n"
            "manager-1 : ok=1 changed=0 unreachable=0 failed=0 skipped=0 "
            "rescued=0 ignored=0\n"
        )
        with pytest.raises(AnsibleError, match=match):
            parse_manager_backend_local_install_execution(
                stdout,
                expected_payload=payload,
                exit_code=0,
            )
    value = json.dumps(_result(payload), sort_keys=True)
    duplicate = value[:-1] + ',"status":"no-change"}'
    encoded = base64.b64encode(duplicate.encode()).decode()
    with pytest.raises(AnsibleError, match="marker is malformed"):
        parse_manager_backend_local_install_execution(
            (
                f"DSV_MANAGER_BACKEND_LOCAL_INSTALL_B64={encoded}\n"
                "PLAY RECAP *****\n"
                "manager-1 : ok=1 changed=0 unreachable=0 failed=0 skipped=0 "
                "rescued=0 ignored=0\n"
            ),
            expected_payload=payload,
            exit_code=0,
        )
    with pytest.raises(AnsibleError, match="exceeds the evidence limit"):
        parse_manager_backend_local_install_execution(
            "x" * (512 * 1024 + 1),
            expected_payload=payload,
            exit_code=0,
        )


def test_payload_refuses_target_platform_evidence_and_source_drift(
    contract,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = contract.current
    common = (
        current.metadata,
        current.observation,
        current.inventory,
        current.readiness,
        current.scope.base_os,
        current.scope.manager_server,
        contract.reconciliation,
        contract.installation_context,
        contract.installation_plan,
    )
    with pytest.raises(StateConflictError, match="single manager target"):
        build_manager_backend_local_install_payload(
            *common,
            logical_id="manager-2",
            image_filter=current.scope.image_filter,
            architecture=current.scope.architecture,
        )
    with pytest.raises(StateConflictError, match=r"Ubuntu 24\.04"):
        build_manager_backend_local_install_payload(
            *common,
            logical_id="manager-1",
            image_filter=ImageFilter("Ubuntu", "25.04", ImageVersionMatch.EXACT),
            architecture=current.scope.architecture,
        )
    stale_manager = replace(
        current.scope.manager_server,
        service_inactive=False,
    )
    with pytest.raises(StateConflictError, match="install-only Manager evidence"):
        build_manager_backend_local_install_payload(
            *common[:5],
            stale_manager,
            *common[6:],
            logical_id="manager-1",
            image_filter=current.scope.image_filter,
            architecture=current.scope.architecture,
        )
    source = load_ansible_source_bundle()
    monkeypatch.setattr(
        install_module,
        "load_ansible_source_bundle",
        lambda: replace(source, digest="sha256:" + "0" * 64),
    )
    with pytest.raises(StateConflictError, match="context source conflicts"):
        build_manager_backend_local_install_payload(
            *common,
            logical_id="manager-1",
            image_filter=current.scope.image_filter,
            architecture=current.scope.architecture,
        )


@pytest.mark.parametrize(
    ("check", "status"),
    [
        (False, "no-change"),
        (True, "not-predicted"),
    ],
)
def test_service_executes_exact_source_and_redacts_output(
    contract,
    tmp_path: Path,
    check: bool,
    status: str,
) -> None:
    payload = _payload(contract)
    stdout, exit_code = _stdout(
        payload,
        status,
        extra="10.0.0.11 token=obviously-fake\n",
    )
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(exit_code, stdout, "token=obviously-fake"),
        ]
    )
    service = AnsibleService(
        _builder(tmp_path, contract.prepared.paths),
        runner,
    )
    current = contract.current
    with ClusterLock(contract.prepared.paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_manager_backend_local_install(
            lock,
            current.metadata,
            current.observation,
            current.inventory,
            current.scope.base_os,
            current.scope.manager_server,
            contract.reconciliation,
            contract.installation_context,
            contract.installation_plan,
            limit=("manager-1",),
            readiness=current.readiness,
            image_filter=current.scope.image_filter,
            architecture=current.scope.architecture,
            check=check,
        )
    assert result.manager_backend_local_install is not None
    assert result.manager_backend_local_install.status.value == status
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {
        "deploy_scylla_vms_manager_backend_local_install": payload
    }
    assert ("--check" in runner.specs[-1].argv) is check
    assert "manager-1" in runner.specs[-1].argv
    assert "10.0.0.11" in runner.specs[-1].sensitive_values
    assert "obviously-fake" not in repr(result)


def test_service_redacts_timeout_and_cleans_runtime_payload(
    contract,
    tmp_path: Path,
) -> None:
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, contract.prepared.paths), runner)
    current = contract.current
    with ClusterLock(contract.prepared.paths, "deploy", 0) as lock:
        service.version(lock)
        runner.error = ProcessTimeoutError("token=obviously-fake")
        with pytest.raises(
            AnsibleError, match="manager-backend-local-install command failed"
        ) as caught:
            service.execute_manager_backend_local_install(
                lock,
                current.metadata,
                current.observation,
                current.inventory,
                current.scope.base_os,
                current.scope.manager_server,
                contract.reconciliation,
                contract.installation_context,
                contract.installation_plan,
                limit=("manager-1",),
                readiness=current.readiness,
                image_filter=current.scope.image_filter,
                architecture=current.scope.architecture,
            )
    assert "obviously-fake" not in str(caught.value)
    assert not tuple(contract.prepared.paths.ansible_local_tmp.iterdir())


def test_registry_source_and_static_package_boundary() -> None:
    definition = get_playbook("manager-backend-local-install")
    assert definition.source_available
    assert definition.hosts == "manager"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.MUTATING
    assert definition.tags == (
        "manager-backend-local-install",
        "preflight",
        "packages",
        "verify",
    )
    assert callable(AnsibleService.execute_manager_backend_local_install)
    source_paths = {item.path for item in load_ansible_source_bundle().files}
    assert set(MANAGER_BACKEND_LOCAL_INSTALL_SOURCE_PATHS) <= source_paths

    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/manager-backend-local-install.yml").read_text()
    role = (
        root / "playbooks/roles/manager_backend_local_install/tasks/main.yml"
    ).read_text()
    provenance = (
        root
        / (
            "playbooks/roles/manager_backend_local_install/files/"
            "manager-backend-local-install.provenance.yml"
        )
    ).read_text()
    combined = playbook + role + provenance
    for required in (
        "hosts: manager",
        "serial: 1",
        "any_errors_fatal: true",
        "policy_rc_d: 101",
        "masked: true",
        "state: stopped",
        SCYLLA_PACKAGE_VERSION,
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST,
        "storage_preparation_performed': false",
        "storage_filesystem_mutation_performed': false",
        "storage_mount_mutation_performed': false",
        "manager_configuration_performed': false",
        "scylla_configuration_rendering_performed': false",
        "schema_or_keyspace_performed': false",
        "cql_performed': false",
    ):
        assert required in combined
    lowered = combined.lower()
    for forbidden in (
        "ansible.builtin.shell:",
        "ansible.builtin.get_url:",
        "apt_key:",
        "state: started",
        "state: latest",
        "scyllamgr_agent_setup",
        "scylla-manager.yaml",
        "sctool ",
        "nodetool ",
        "mkfs",
        "mount:",
        "upstream_role_commit",
    ):
        assert forbidden not in lowered
