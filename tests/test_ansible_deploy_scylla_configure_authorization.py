import inspect
import json
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_install_reconciliation import (
    _call as _reconcile_install,
)
from test_ansible_deploy_scylla_install_reconciliation import (
    _complete as _complete_install,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_scylla_configure_authorization as authorization_module
from scylla_vms.ansible.deploy_plan import _digest_object
from scylla_vms.ansible.deploy_scylla_configure_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaConfigureApprovalMethod,
    DeployScyllaConfigureArchitecture,
    DeployScyllaConfigureAuthorizationArtifactState,
    DeployScyllaConfigureAuthorizationProof,
    DeployScyllaConfigureAuthorizationStore,
    DeployScyllaConfigureSeedPolicy,
    DeployScyllaConfigureServicePolicy,
    _derive_authorization_scopes,
    _load_authorization_context,
    authorize_deploy_scylla_configure,
    deploy_scylla_configure_authorization_id_from_filename,
    deploy_scylla_configure_authorization_path,
)
from scylla_vms.ansible.scylla_configure import (
    SCYLLA_CONFIGURE_DIRECTORIES,
    ScyllaSeedPolicy,
    SeedSelectionMode,
)
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
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

_PRIVATE_PATH = "/private/operator/scylla-configure-authorization.json"
_SECRET = "obviously-fake-scylla-configure-authorization-secret"
_PROMPT = "APPROVE seeds and 10.0.0.20 with key material?"


def _proof(
    method: DeployScyllaConfigureApprovalMethod = (
        DeployScyllaConfigureApprovalMethod.INTERACTIVE
    ),
) -> DeployScyllaConfigureAuthorizationProof:
    return DeployScyllaConfigureAuthorizationProof(
        approval_method=method,
        approved=True,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = _complete_install(tmp_path, monkeypatch, "installed")
    _reconcile_install(prepared)
    return prepared, runner


def _call(prepared, proof: DeployScyllaConfigureAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_scylla_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployScyllaConfigureAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployScyllaConfigureApprovalMethod.INTERACTIVE,
        DeployScyllaConfigureApprovalMethod.CLI_YES,
    ),
)
def test_exact_derived_intent_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: DeployScyllaConfigureApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_scylla_configure)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "target",
        "config",
        "topology",
        "seed",
        "version",
        "address",
        "variable",
        "command",
        "path",
        "scope",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    path = deploy_scylla_configure_authorization_path(prepared.paths, OPERATION_ID)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item for item in prepared.paths.operations.iterdir() if item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}
    show_before = _run_show(prepared.paths)

    report = _call(prepared, _proof(method))
    first_bytes = path.read_bytes()
    reused = _call(prepared, _proof(method))
    stored = _record(prepared)
    show_after = _run_show(prepared.paths)

    assert (
        report.artifact_state is DeployScyllaConfigureAuthorizationArtifactState.CREATED
    )
    assert (
        reused.artifact_state is DeployScyllaConfigureAuthorizationArtifactState.REUSED
    )
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count
    assert show_after == show_before
    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert report.authorization_schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    assert report.proof_schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.approval_method is method
    assert report.classification is OperationClassification.MUTATING
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.consumed
    assert report.execution_state == "unavailable"

    record = stored.record
    assert record.authorization_state == "authorized-pre-execution"
    assert not record.consumed
    assert record.execution_state == "unavailable"
    assert record.target_count == len(record.scopes) == 1
    scope = record.scopes[0]
    assert scope.mapping_sequence == 12
    assert scope.classification is OperationClassification.MUTATING
    assert scope.architecture is DeployScyllaConfigureArchitecture.AMD64
    assert scope.service_policy is DeployScyllaConfigureServicePolicy.MASKED_INACTIVE
    assert scope.seed_policy is DeployScyllaConfigureSeedPolicy.INITIAL_STABLE_ID
    assert scope.seed_count == 1
    assert scope.directory_count == len(SCYLLA_CONFIGURE_DIRECTORIES)
    assert scope.rendered_file_count == 2
    assert scope.template_count == 2
    assert scope.package_version_digest == _digest_object(SCYLLA_PACKAGE_VERSION)
    assert scope.directory_policy_digest == _digest_object(
        list(SCYLLA_CONFIGURE_DIRECTORIES)
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
        "scylla-ad-1-1",
        '"cluster_name":"example"',
        '"datacenter":"',
        '"rack":"',
        "seed_stable_ids",
        "SimpleSeedProvider",
        "/var/lib/scylla",
        "ansible-playbook",
        "--limit",
    ):
        assert protected not in public
    assert deploy_scylla_configure_authorization_id_from_filename(path.name) == (
        OPERATION_ID
    )
    assert (
        deploy_scylla_configure_authorization_id_from_filename(f"uppercase-{path.name}")
        is None
    )


@pytest.mark.parametrize(
    ("proof", "message"),
    (
        (DeployScyllaConfigureAuthorizationProof(), "approval is required"),
        (
            DeployScyllaConfigureAuthorizationProof(
                approval_method=DeployScyllaConfigureApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
        (
            DeployScyllaConfigureAuthorizationProof(
                approval_method=DeployScyllaConfigureApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployScyllaConfigureAuthorizationProof(
                approval_method=DeployScyllaConfigureApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployScyllaConfigureAuthorizationProof(
                approval_method=DeployScyllaConfigureApprovalMethod.INTERACTIVE,
                approved=True,
                narrow_consent_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
    ),
)
def test_refuses_missing_denied_destructive_and_narrow_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployScyllaConfigureAuthorizationProof,
    message: str,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof)
    assert len(runner.specs) == process_count
    assert not deploy_scylla_configure_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_configuration_derivation_refuses_every_scope_and_safety_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_authorization_context(prepared.paths, OPERATION_ID, lock=lock)
        loaded = authorization_module._loaded(context)
        inventory_host = next(
            host
            for host in loaded.planning.base.deploy.inventory.record.inventory.hosts
            if host.role.value == "scylla"
        )
        install_entry = context.install.evidence.record.entries[0]
        storage_entry = context.install.authorization_context.evidence.record.entries[0]
        base_store = authorization_module.DeployNonJumpBaseOsEvidenceStore(
            prepared.paths, OPERATION_ID
        )
        base = base_store.read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        base_host = next(
            host
            for entry in base.record.entries
            for host in entry.hosts
            if host.logical_id == inventory_host.logical_id
        )

        original_rack = inventory_host.scylla_rack
        object.__setattr__(inventory_host, "scylla_rack", "wrong-rack")
        with pytest.raises(StateConflictError, match="topology"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(inventory_host, "scylla_rack", original_rack)

        original_dc = inventory_host.scylla_datacenter
        object.__setattr__(inventory_host, "scylla_datacenter", "wrong-dc")
        with pytest.raises(StateConflictError, match="topology"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(inventory_host, "scylla_datacenter", original_dc)

        original_address = inventory_host.private_address
        object.__setattr__(inventory_host, "private_address", "203.0.113.20")
        with pytest.raises(StateConflictError, match="RFC 1918"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(inventory_host, "private_address", original_address)

        original_version = install_entry.package_version
        object.__setattr__(install_entry, "package_version", "2026.1.invalid")
        with pytest.raises(StateConflictError, match="install"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(install_entry, "package_version", original_version)

        object.__setattr__(install_entry, "service_masked", False)
        with pytest.raises(StateConflictError, match="service"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(install_entry, "service_masked", True)

        object.__setattr__(storage_entry, "readiness_for_scylla", False)
        with pytest.raises(StateConflictError, match="storage"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(storage_entry, "readiness_for_scylla", True)

        original_base_read = (
            authorization_module.DeployNonJumpBaseOsEvidenceStore.read_locked
        )
        monkeypatch.setattr(
            authorization_module.DeployNonJumpBaseOsEvidenceStore,
            "read_locked",
            lambda *_args, **_kwargs: base,
        )
        object.__setattr__(base_host, "reboot_required", True)
        with pytest.raises(StateConflictError, match="base-os"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(base_host, "reboot_required", False)
        monkeypatch.setattr(
            authorization_module.DeployNonJumpBaseOsEvidenceStore,
            "read_locked",
            original_base_read,
        )

        original_files = loaded.source.files
        object.__setattr__(
            loaded.source,
            "files",
            tuple(
                item
                for item in original_files
                if not item.path.endswith("templates/scylla.yaml.j2")
            ),
        )
        with pytest.raises(StateConflictError, match="source binding is incomplete"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        object.__setattr__(loaded.source, "files", original_files)

        original_selector = authorization_module.select_scylla_seeds
        monkeypatch.setattr(
            authorization_module,
            "select_scylla_seeds",
            lambda *_args, **_kwargs: ScyllaSeedPolicy(
                SeedSelectionMode.INITIAL,
                ("unknown-seed",),
                _digest_object(
                    {
                        "mode": SeedSelectionMode.INITIAL.value,
                        "stable_ids": ["unknown-seed"],
                    }
                ),
            ),
        )
        with pytest.raises(StateConflictError, match="seed"):
            _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
        monkeypatch.setattr(
            authorization_module, "select_scylla_seeds", original_selector
        )

        assert _derive_authorization_scopes(context, paths=prepared.paths, lock=lock)
    assert len(runner.specs) == process_count


def test_refuses_missing_drifted_later_state_wrong_lock_and_changed_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    reconciliation_path = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-scylla-install-reconciliation.json"
    )
    original = reconciliation_path.read_bytes()
    reconciliation_path.unlink()
    with pytest.raises(StateConflictError, match="requires complete"):
        _call(prepared, _proof())
    reconciliation_path.write_bytes(original)
    reconciliation_path.chmod(0o600)

    later = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-scylla-configure-execution.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, _proof())
    later.unlink()

    trust_path = prepared.paths.ansible_trust
    trust_original = trust_path.read_bytes()
    trust = cast(dict[str, object], json.loads(trust_original))
    trust["generation"] = cast(int, trust["generation"]) + 1
    trust_path.write_text(json.dumps(trust) + "\n", encoding="utf-8")
    trust_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, _proof())
    trust_path.write_bytes(trust_original)
    trust_path.chmod(0o600)

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_scylla_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_proof(),
        )

    _call(prepared, _proof())
    with pytest.raises(StateConflictError, match="changed"):
        _call(
            prepared,
            _proof(DeployScyllaConfigureApprovalMethod.CLI_YES),
        )
    assert len(runner.specs) == process_count


def test_store_path_tamper_symlink_and_show_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _call(prepared, _proof())
    path = deploy_scylla_configure_authorization_path(prepared.paths, OPERATION_ID)
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
