import inspect
import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_preflight_execution import (
    ManagerBackendPreflightRunner,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _call as _execute_preflight,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _prepared as _prepare_preflight_execution,
)
from test_ansible_deploy_manager_backend_preflight_reconciliation import (
    _call as _reconcile_preflight,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_backend_installation_plan as installation_module
import scylla_vms.ansible.deploy_manager_backend_local_install_authorization as authorization_module
import scylla_vms.ansible.manager_backend_local_install as local_install_module
from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    deploy_manager_backend_installation_plan_path,
    plan_deploy_manager_backend_local_installation,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_authorization import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION,
    DeployManagerBackendLocalInstallApprovalMethod,
    DeployManagerBackendLocalInstallArchitecture,
    DeployManagerBackendLocalInstallAuthorizationArtifactState,
    DeployManagerBackendLocalInstallAuthorizationProof,
    DeployManagerBackendLocalInstallAuthorizationStore,
    DeployManagerBackendLocalInstallPackagePolicy,
    DeployManagerBackendLocalInstallServicePolicy,
    _build_payload,
    _derive_authorization_scope,
    _derive_package_provenance,
    _load_authorization_context,
    authorize_deploy_manager_backend_local_install,
    deploy_manager_backend_local_install_authorization_id_from_filename,
    deploy_manager_backend_local_install_authorization_path,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_REPOSITORY_URI,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json
from scylla_vms.terraform.apply_readiness import terraform_apply_readiness_path

_PRIVATE_PATH = "/private/operator/manager-backend-local-install.json"
_SECRET = "obviously-fake-manager-backend-local-install-secret"
_PROMPT = "APPROVE local backend packages for 10.0.0.30?"


def _proof(
    method: DeployManagerBackendLocalInstallApprovalMethod = (
        DeployManagerBackendLocalInstallApprovalMethod.INTERACTIVE
    ),
) -> DeployManagerBackendLocalInstallAuthorizationProof:
    return DeployManagerBackendLocalInstallAuthorizationProof(
        approval_method=method,
        approved=True,
    )


@pytest.fixture(scope="module")
def authorization_baseline(tmp_path_factory: pytest.TempPathFactory):
    monkeypatch = pytest.MonkeyPatch()
    root = tmp_path_factory.mktemp("manager-backend-local-install-authorization")
    foundation = root / "foundation"
    foundation.mkdir()
    prepared, executables, toolchain = _prepare_preflight_execution(
        foundation, monkeypatch
    )
    runner = ManagerBackendPreflightRunner()
    _execute_preflight(prepared, runner, executables, toolchain)
    _reconcile_preflight(prepared)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        plan_deploy_manager_backend_local_installation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )
    snapshot = root / "ready-snapshot"
    shutil.copytree(prepared.paths.state_root, snapshot)
    yield prepared, runner, snapshot
    monkeypatch.undo()


@pytest.fixture
def ready_baseline(authorization_baseline, monkeypatch: pytest.MonkeyPatch):
    prepared, runner, snapshot = authorization_baseline
    shutil.rmtree(prepared.paths.state_root)
    shutil.copytree(snapshot, prepared.paths.state_root)
    for module in (
        installation_module,
        local_install_module,
        authorization_module,
    ):
        monkeypatch.setattr(
            module,
            "validate_scylla_signing_key",
            lambda _key: None,
        )
    return prepared, runner


def _call(
    prepared,
    proof: DeployManagerBackendLocalInstallAuthorizationProof,
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_manager_backend_local_install(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployManagerBackendLocalInstallAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def _write_document(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)


@pytest.mark.parametrize(
    "method",
    (
        DeployManagerBackendLocalInstallApprovalMethod.INTERACTIVE,
        DeployManagerBackendLocalInstallApprovalMethod.CLI_YES,
    ),
)
def test_exact_package_scope_is_immutable_redacted_and_process_free(
    ready_baseline,
    method: DeployManagerBackendLocalInstallApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_manager_backend_local_install)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "step",
        "target",
        "package",
        "version",
        "repository",
        "key",
        "command",
        "variable",
        "path",
        "scope",
        "prompt",
        "text",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = ready_baseline
    assert runner.specs is not None
    process_count = len(runner.specs)
    path = deploy_manager_backend_local_install_authorization_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item for item in prepared.paths.operations.iterdir() if item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}

    report = _call(prepared, _proof(method))
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    reused = _call(prepared, _proof(method))
    stored = _record(prepared)

    assert (
        report.artifact_state
        is DeployManagerBackendLocalInstallAuthorizationArtifactState.CREATED
    )
    assert (
        reused.artifact_state
        is DeployManagerBackendLocalInstallAuthorizationArtifactState.REUSED
    )
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count
    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert (
        report.authorization_schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    assert (
        report.proof_schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.approval_method is method
    assert report.classification is OperationClassification.MUTATING
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.target_stable_id == "manager-1"
    assert report.target_count == 1
    assert report.package_count == len(SCYLLA_PACKAGES)
    assert report.architecture is DeployManagerBackendLocalInstallArchitecture.AMD64
    assert (
        report.package_policy
        is DeployManagerBackendLocalInstallPackagePolicy.PACKAGE_ONLY
    )
    assert (
        report.service_policy
        is DeployManagerBackendLocalInstallServicePolicy.MASKED_INACTIVE
    )
    assert report.prohibited_action_count == 0
    assert not report.consumed
    assert report.execution_state == "unavailable"
    assert report.finalization_state == "not-started"
    assert report.public_workflow_state == "unavailable"

    record = stored.record
    assert record.authorization_state == "authorized-pre-execution"
    assert not record.consumed
    assert record.execution_state == "unavailable"
    assert record.scope.step_sequence == 1
    assert record.scope.boundary == "package-install"
    assert record.scope.playbook == "manager-backend-local-install"
    assert record.scope.target_role == "manager"
    assert record.scope.target_stable_id == "manager-1"
    assert record.scope.package_install_permitted
    assert not any(
        (
            record.scope.setup_permitted,
            record.scope.storage_mutation_permitted,
            record.scope.tuning_permitted,
            record.scope.configuration_permitted,
            record.scope.schema_permitted,
            record.scope.manager_actions_permitted,
            record.scope.service_start_permitted,
        )
    )

    persisted = json.loads(first_bytes)
    assert first_bytes == serialize_json(persisted)
    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        _PROMPT,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        SCYLLA_REPOSITORY_URI,
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_PACKAGE_VERSION,
        "BEGIN PGP",
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
    ):
        assert protected not in public
    assert (
        deploy_manager_backend_local_install_authorization_id_from_filename(path.name)
        == OPERATION_ID
    )
    assert (
        deploy_manager_backend_local_install_authorization_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_refuses_missing_denied_destructive_narrow_and_changed_proofs(
    ready_baseline,
) -> None:
    cases = (
        (
            DeployManagerBackendLocalInstallAuthorizationProof(),
            "approval is required",
        ),
        (
            DeployManagerBackendLocalInstallAuthorizationProof(
                approval_method=(
                    DeployManagerBackendLocalInstallApprovalMethod.INTERACTIVE
                ),
                approved=False,
            ),
            "approval was denied",
        ),
        (
            DeployManagerBackendLocalInstallAuthorizationProof(
                approval_method=DeployManagerBackendLocalInstallApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployManagerBackendLocalInstallAuthorizationProof(
                approval_method=(
                    DeployManagerBackendLocalInstallApprovalMethod.INTERACTIVE
                ),
                approved=True,
                destructive_scope_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployManagerBackendLocalInstallAuthorizationProof(
                approval_method=(
                    DeployManagerBackendLocalInstallApprovalMethod.INTERACTIVE
                ),
                approved=True,
                narrow_consent_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
    )
    prepared, runner = ready_baseline
    assert runner.specs is not None
    process_count = len(runner.specs)
    for proof, message in cases:
        with pytest.raises(StateConflictError, match=message):
            _call(prepared, proof)
    path = deploy_manager_backend_local_install_authorization_path(
        prepared.paths, OPERATION_ID
    )
    assert not path.exists()

    _call(prepared, _proof())
    with pytest.raises(StateConflictError, match="changed"):
        _call(
            prepared,
            _proof(DeployManagerBackendLocalInstallApprovalMethod.CLI_YES),
        )
    assert len(runner.specs) == process_count


def test_refuses_wrong_lock_missing_plan_later_history_and_dedicated_storage_gate(
    ready_baseline,
) -> None:
    prepared, runner = ready_baseline
    assert runner.specs is not None
    process_count = len(runner.specs)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_manager_backend_local_install(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_proof(),
        )

    plan_path = deploy_manager_backend_installation_plan_path(
        prepared.paths, OPERATION_ID
    )
    plan_bytes = plan_path.read_bytes()
    plan_path.unlink()
    with pytest.raises(StateConflictError, match="exact installation plan"):
        _call(prepared, _proof())
    plan_path.write_bytes(plan_bytes)
    plan_path.chmod(0o600)

    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-backend-local-install-execution.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, _proof())
    later.unlink()

    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_authorization_context(prepared.paths, OPERATION_ID, lock=lock)
        payload = _build_payload(context)
        package = _derive_package_provenance(context, payload)
        storage = context.installation_context.record.storage_decision
        object.__setattr__(storage, "dedicated_volume_identified", False)
        with pytest.raises(StateConflictError, match="exact evidence-ready"):
            _derive_authorization_scope(context, payload, package)
    assert len(runner.specs) == process_count


def test_refuses_observation_inventory_trust_and_readiness_drift(
    ready_baseline,
) -> None:
    prepared, runner = ready_baseline
    assert runner.specs is not None
    process_count = len(runner.specs)
    paths = (
        prepared.paths.terraform_observed,
        prepared.paths.ansible_inventory,
        prepared.paths.ansible_trust,
        terraform_apply_readiness_path(prepared.paths, OPERATION_ID),
    )
    for path in paths:
        original = path.read_bytes()
        with path.open("ab") as stream:
            stream.write(b" ")
        with pytest.raises((StateConflictError, StatePersistenceError)):
            _call(prepared, _proof())
        path.write_bytes(original)
        path.chmod(0o600)
    assert not deploy_manager_backend_local_install_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert len(runner.specs) == process_count


def test_refuses_stale_plan_and_source_or_catalog_drift(
    ready_baseline,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = ready_baseline
    assert runner.specs is not None
    process_count = len(runner.specs)
    plan_path = deploy_manager_backend_installation_plan_path(
        prepared.paths, OPERATION_ID
    )
    original_plan = cast(dict[str, object], json.loads(plan_path.read_bytes()))
    stale_plan = cast(dict[str, object], json.loads(plan_path.read_bytes()))
    steps = cast(list[dict[str, object]], stale_plan["steps"])
    package_step = steps[0]
    package_step.update(
        {
            "authorization_requirement": "blocked-before-authorization",
            "blockers": [
                "manager-backend-package-install-source-unavailable",
            ],
            "source_contract_state": "manager-role-source-unavailable",
            "source_digest": None,
            "source_state": "source-unavailable",
            "status": "blocked",
        }
    )
    package_step["blocker_digest"] = installation_module._digest_object(
        package_step["blockers"]
    )
    package_step["step_digest"] = installation_module._record_digest_from_values(
        package_step, "step_digest"
    )
    blockers = sorted(
        {blocker for step in steps for blocker in cast(list[str], step["blockers"])}
    )
    stale_plan.update(
        {
            "authorization_state": "unavailable",
            "blocked_count": 9,
            "blockers": blockers,
            "blocker_count": len(blockers),
            "blocker_digest": installation_module._digest_object(blockers),
            "next_implementation_contract": (
                "manager-backend-local-package-install-source-contract"
            ),
            "source_available_count": 0,
            "source_unavailable_count": 9,
        }
    )
    stale_plan["plan_digest"] = installation_module._record_digest_from_values(
        stale_plan, "plan_digest"
    )
    _write_document(plan_path, stale_plan)
    with pytest.raises(StateConflictError, match="immutable"):
        _call(prepared, _proof())

    _write_document(plan_path, original_plan)
    catalog_digest = authorization_module.ansible_operation_catalog_digest
    monkeypatch.setattr(
        authorization_module,
        "ansible_operation_catalog_digest",
        lambda: "0" * 64,
    )
    with pytest.raises(StateConflictError, match="source drifted"):
        _call(prepared, _proof())
    monkeypatch.setattr(
        authorization_module,
        "ansible_operation_catalog_digest",
        catalog_digest,
    )

    source = local_install_module.load_ansible_source_bundle()
    monkeypatch.setattr(
        local_install_module,
        "load_ansible_source_bundle",
        lambda: replace(source, digest="0" * 64),
    )
    with pytest.raises(StateConflictError, match="source"):
        _call(prepared, _proof())
    assert not deploy_manager_backend_local_install_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert len(runner.specs) == process_count


def test_store_rejects_tamper_symlink_and_show_validates(
    ready_baseline,
) -> None:
    prepared, _runner = ready_baseline
    _call(prepared, _proof())
    path = deploy_manager_backend_local_install_authorization_path(
        prepared.paths, OPERATION_ID
    )
    original = path.read_bytes()
    document = cast(dict[str, object], json.loads(original))
    document["target_count"] = 2
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _record(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    path.write_bytes(original)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
    target = path.with_name(f"{path.name}.target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _record(prepared)
