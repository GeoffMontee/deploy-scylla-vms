import inspect
import json
import os
import shutil
import subprocess
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_terraform_operation_composition import (
    _compose,
    _prepare,
    _read_journal,
    _rewrite_json,
)
from test_terraform_plan_checkpoint import (
    ADDRESS_MARKER,
    OPERATION_ID,
    SECRET_MARKER,
    _change,
)

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationJournalStore, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import AtomicJsonFile, serialize_json
from scylla_vms.terraform.apply_authorization import (
    TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    TERRAFORM_APPLY_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION,
    TerraformApplyAuthorizationClass,
    TerraformApplyAuthorizationProof,
    TerraformApplyAuthorizationResult,
    TerraformApplyAuthorizationState,
    TerraformApplyAuthorizationStore,
    TerraformApplyDriftAcknowledgement,
    TerraformApplyOrdinaryApproval,
    TerraformApplyScopeProofState,
    TerraformDestructiveScopeProof,
    authorize_deploy_apply,
    terraform_apply_authorization_path,
)
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.plan import TerraformPlanCheckpointStore

_OTHER_OPERATION_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
_OTHER_DIGEST = "sha256:" + "d" * 64
_OPERATOR_MARKER = "obviously-fake-operator@example.invalid"
_PROMPT_MARKER = "APPROVE SHOULD-NOT-PERSIST?"


def _authorize(prepared, proof: TerraformApplyAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            proof,
        )


def _ordinary(
    source: TerraformApplyOrdinaryApproval = TerraformApplyOrdinaryApproval.INTERACTIVE,
) -> TerraformApplyAuthorizationProof:
    return TerraformApplyAuthorizationProof(ordinary_approval=source)


def _destructive_proof(prepared) -> TerraformApplyAuthorizationProof:
    checkpoint = TerraformPlanCheckpointStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=_checkpoint_cluster_uuid(prepared),
        expected_cluster_name="example",
        expected_operation="deploy",
    )
    return TerraformApplyAuthorizationProof(
        ordinary_approval=TerraformApplyOrdinaryApproval.CLI_YES,
        allow_destructive=True,
        destructive_scope=TerraformDestructiveScopeProof.from_summary(
            checkpoint.record.summary
        ),
    )


def _checkpoint_cluster_uuid(prepared) -> uuid.UUID:
    value = json.loads(
        (
            prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
        ).read_text(encoding="utf-8")
    )
    return uuid.UUID(value["cluster_uuid"])


def _authorization_path(prepared) -> Path:
    return terraform_apply_authorization_path(prepared.paths, OPERATION_ID)


def test_no_change_plan_reports_not_required_without_persistence(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path, resource_changes=[])
    _compose(prepared)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    report = _authorize(prepared, TerraformApplyAuthorizationProof())

    assert report.schema_version == (
        TERRAFORM_APPLY_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert report.result is TerraformApplyAuthorizationResult.NOT_REQUIRED
    assert report.authorization_class is TerraformApplyAuthorizationClass.NOT_REQUIRED
    assert report.authorization_state is TerraformApplyAuthorizationState.NOT_REQUIRED
    assert report.apply_required is False
    assert report.authorization_digest is None
    assert report.apply_execution == "unavailable"
    assert report.execution_intent == "not-started"
    assert report.state_backup == "unavailable"
    assert report.to_object()["execution"]["apply_command_available"] is False
    assert not _authorization_path(prepared).exists()
    assert journal_path.read_bytes() == journal_before

    with pytest.raises(StateConflictError, match="must not manufacture"):
        _authorize(prepared, _ordinary())


@pytest.mark.parametrize(
    ("changes", "source"),
    [
        (
            [_change("oci_core_instance.created", ["create"])],
            TerraformApplyOrdinaryApproval.INTERACTIVE,
        ),
        (
            [_change("oci_core_instance.updated", ["update"])],
            TerraformApplyOrdinaryApproval.CLI_YES,
        ),
    ],
)
def test_create_and_update_plans_accept_documented_ordinary_approval(
    tmp_path: Path,
    changes: list[dict[str, object]],
    source: TerraformApplyOrdinaryApproval,
) -> None:
    prepared = _prepare(tmp_path, resource_changes=changes)
    _compose(prepared)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    report = _authorize(prepared, _ordinary(source))
    stored = TerraformApplyAuthorizationStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=_checkpoint_cluster_uuid(prepared),
        expected_cluster_name="example",
    )

    assert report.result is TerraformApplyAuthorizationResult.CREATED
    assert report.authorization_class is TerraformApplyAuthorizationClass.MUTATING
    assert report.authorization_state is (
        TerraformApplyAuthorizationState.AUTHORIZED_PRE_EXECUTION
    )
    assert report.apply_required is True
    assert report.ordinary_approval is source
    assert report.allow_destructive is False
    assert report.destructive_scope is TerraformApplyScopeProofState.NOT_REQUIRED
    assert stored.record.schema_version == (
        TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
    )
    assert stored.record.proof.schema_version == (
        TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert stored.record.authorization_digest == report.authorization_digest
    assert stored.record.journal_generation == 2
    assert stored.record.journal_phase is OperationPhase.PLAN
    assert stored.record.journal_status is JournalStatus.IN_PROGRESS
    assert stored.record.apply_execution == "unavailable"
    assert stored.record.state_backup == "unavailable"
    assert _authorization_path(prepared).stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_before


@pytest.mark.parametrize(
    ("proof_factory", "message"),
    [
        (
            lambda prepared: TerraformApplyAuthorizationProof(
                ordinary_approval=TerraformApplyOrdinaryApproval.CLI_YES,
            ),
            "allow-destructive",
        ),
        (
            lambda prepared: TerraformApplyAuthorizationProof(
                ordinary_approval=TerraformApplyOrdinaryApproval.CLI_YES,
                allow_destructive=True,
            ),
            "exact scope",
        ),
        (
            lambda prepared: TerraformApplyAuthorizationProof(
                ordinary_approval=TerraformApplyOrdinaryApproval.CLI_YES,
                allow_destructive=True,
                destructive_scope=replace(
                    _destructive_proof(prepared).destructive_scope,
                    destructive_scope_digest=_OTHER_DIGEST,
                ),
            ),
            "does not match",
        ),
    ],
)
def test_destructive_plan_requires_allow_flag_and_exact_scope(
    tmp_path: Path,
    proof_factory,
    message: str,
) -> None:
    prepared = _prepare(
        tmp_path,
        resource_changes=[
            _change("oci_core_instance.replaced", ["delete", "create"]),
            _change("oci_core_instance.deleted", ["delete"]),
        ],
    )
    _compose(prepared)

    with pytest.raises(StateConflictError, match=message):
        _authorize(prepared, proof_factory(prepared))

    assert not _authorization_path(prepared).exists()


def test_exact_destructive_proof_is_separate_and_address_free(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        resource_changes=[
            _change('oci_core_instance.host["private-node"]', ["delete", "create"]),
            _change("oci_core_volume.deleted", ["delete"]),
        ],
    )
    _compose(prepared)
    proof = _destructive_proof(prepared)

    report = _authorize(prepared, proof)
    persisted = _authorization_path(prepared).read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)

    assert report.authorization_class is TerraformApplyAuthorizationClass.DESTRUCTIVE
    assert report.allow_destructive is True
    assert report.destructive_scope is TerraformApplyScopeProofState.MATCHED
    assert report.ordinary_approval is TerraformApplyOrdinaryApproval.CLI_YES
    for protected in (
        "oci_core_instance",
        "private-node",
        ADDRESS_MARKER,
        SECRET_MARKER,
        _OPERATOR_MARKER,
        _PROMPT_MARKER,
        str(tmp_path),
    ):
        assert protected not in persisted
        assert protected not in projected


def test_benign_refresh_drift_requires_separate_interactive_review(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        resource_changes=[_change("oci_core_instance.updated", ["update"])],
        resource_drift=[_change("oci_core_instance.drifted", ["update"])],
    )
    _compose(prepared)

    with pytest.raises(StateConflictError, match="separate interactive review"):
        _authorize(
            prepared,
            _ordinary(TerraformApplyOrdinaryApproval.CLI_YES),
        )

    report = _authorize(
        prepared,
        TerraformApplyAuthorizationProof(
            ordinary_approval=TerraformApplyOrdinaryApproval.CLI_YES,
            drift_acknowledgement=(
                TerraformApplyDriftAcknowledgement.INTERACTIVE_REVIEW
            ),
        ),
    )
    assert report.drift_acknowledgement is (
        TerraformApplyDriftAcknowledgement.INTERACTIVE_REVIEW
    )


def test_conflicting_refresh_drift_is_never_authorized(tmp_path: Path) -> None:
    prepared = _prepare(
        tmp_path,
        resource_changes=[_change("oci_core_instance.updated", ["update"])],
        resource_drift=[_change("oci_core_instance.drifted", ["delete"])],
    )
    _compose(prepared)

    with pytest.raises(StateConflictError, match="cannot be authorized"):
        _authorize(
            prepared,
            TerraformApplyAuthorizationProof(
                ordinary_approval=TerraformApplyOrdinaryApproval.INTERACTIVE,
                drift_acknowledgement=(
                    TerraformApplyDriftAcknowledgement.INTERACTIVE_REVIEW
                ),
            ),
        )

    assert not _authorization_path(prepared).exists()


def test_absent_initial_state_allows_only_create_only_drift_free_plan(
    tmp_path: Path,
) -> None:
    (tmp_path / "create").mkdir(mode=0o700)
    create = _prepare(
        tmp_path / "create",
        resource_changes=[_change("oci_core_instance.created", ["create"])],
        write_state=False,
    )
    _compose(create)
    assert _authorize(create, _ordinary()).result is (
        TerraformApplyAuthorizationResult.CREATED
    )

    (tmp_path / "update").mkdir(mode=0o700)
    update = _prepare(
        tmp_path / "update",
        resource_changes=[_change("oci_core_instance.updated", ["update"])],
        write_state=False,
    )
    _compose(update)
    with pytest.raises(StateConflictError, match="absent Terraform state"):
        _authorize(update, _ordinary())
    assert not _authorization_path(update).exists()


def test_exact_reentry_reuses_and_changed_proof_requires_new_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)
    created = _authorize(
        prepared,
        _ordinary(TerraformApplyOrdinaryApproval.INTERACTIVE),
    )
    authorization_before = _authorization_path(prepared).read_bytes()
    journal_before = (prepared.paths.operations / f"{OPERATION_ID}.json").read_bytes()

    def fail_write(self, value, *, expected_digest):
        del self, value, expected_digest
        raise AssertionError("idempotent authorization must not write")

    monkeypatch.setattr(AtomicJsonFile, "write", fail_write)
    reused = _authorize(
        prepared,
        _ordinary(TerraformApplyOrdinaryApproval.INTERACTIVE),
    )

    assert reused.result is TerraformApplyAuthorizationResult.REUSED
    assert reused.authorization_digest == created.authorization_digest
    assert _authorization_path(prepared).read_bytes() == authorization_before
    assert (
        prepared.paths.operations / f"{OPERATION_ID}.json"
    ).read_bytes() == journal_before

    with pytest.raises(StateConflictError, match="create a new plan"):
        _authorize(
            prepared,
            _ordinary(TerraformApplyOrdinaryApproval.CLI_YES),
        )


@pytest.mark.parametrize(
    "artifact",
    [
        "saved-plan",
        "checkpoint",
        "journal",
        "source-record",
        "source-body",
        "tfvars",
        "state",
        "backend",
        "toolchain",
    ],
)
def test_changed_bound_artifacts_fail_before_authorization_persistence(
    tmp_path: Path,
    artifact: str,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)
    checkpoint_path = (
        prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    )
    if artifact == "saved-plan":
        path = prepared.paths.terraform_plans / f"{OPERATION_ID}.tfplan"
        path.write_bytes(path.read_bytes() + b"tampered")
        path.chmod(0o600)
    elif artifact == "checkpoint":
        _rewrite_json(
            checkpoint_path,
            lambda value: value.__setitem__("plan_json_digest", _OTHER_DIGEST),
        )
    elif artifact == "journal":
        journal = _read_journal(prepared)
        advanced = journal.record.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.CONFIRM,
            evidence=journal.record.evidence,
            clock=lambda: datetime(2099, 1, 1, tzinfo=UTC),
        )
        OperationJournalStore(prepared.paths, OPERATION_ID).write(
            advanced,
            expected_generation=journal.record.generation,
            expected_digest=journal.digest,
        )
    elif artifact == "source-record":
        _rewrite_json(
            prepared.paths.terraform_source_record,
            lambda value: None,
            canonical=False,
        )
    elif artifact == "source-body":
        source = prepared.paths.terraform_work / "main.tf"
        source.write_bytes(source.read_bytes() + b"\n# changed\n")
        source.chmod(0o600)
    elif artifact == "tfvars":
        _rewrite_json(
            prepared.paths.terraform_tfvars,
            lambda value: None,
            canonical=False,
        )
    elif artifact == "state":
        prepared.paths.terraform_state.write_bytes(
            prepared.paths.terraform_state.read_bytes() + b"\n"
        )
        prepared.paths.terraform_state.chmod(0o600)
    elif artifact == "backend":
        unexpected = prepared.paths.terraform_work / "terraform.tfstate"
        unexpected.write_text("{}", encoding="utf-8")
        unexpected.chmod(0o600)
    else:
        _rewrite_json(
            checkpoint_path,
            lambda value: value["summary"].__setitem__("terraform_version", "1.7.0"),
        )

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _authorize(prepared, _ordinary())
    assert not _authorization_path(prepared).exists()


def test_wrong_lock_cluster_uuid_operation_id_and_kind_fail_closed(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)
    unlocked = ClusterLock(prepared.paths, "deploy", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        authorize_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            unlocked,
            _ordinary(),
        )
    with (
        ClusterLock(prepared.paths, "redeploy", 0) as wrong_lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        authorize_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            wrong_lock,
            _ordinary(),
        )
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises((StatePersistenceError, UnsafePathError)),
    ):
        authorize_deploy_apply(
            prepared.paths.state_root,
            "example",
            _OTHER_OPERATION_ID,
            lock,
            _ordinary(),
        )

    checkpoint_path = (
        prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    )
    _rewrite_json(
        checkpoint_path,
        lambda value: value.__setitem__(
            "cluster_uuid", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        ),
    )
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _authorize(prepared, _ordinary())


def test_store_refuses_noncanonical_symlink_hardlink_and_permissions(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)
    _authorize(prepared, _ordinary())
    path = _authorization_path(prepared)
    original = path.read_bytes()

    forged = replace(prepared.paths, terraform_plans=tmp_path / "outside")
    with pytest.raises(UnsafePathError, match="not canonical"):
        TerraformApplyAuthorizationStore(forged, OPERATION_ID)

    path.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        TerraformApplyAuthorizationStore(prepared.paths, OPERATION_ID).read(
            expected_cluster_uuid=_checkpoint_cluster_uuid(prepared),
            expected_cluster_name="example",
        )
    path.chmod(0o600)

    path.unlink()
    outside = tmp_path / "outside.json"
    outside.write_bytes(original)
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(UnsafePathError, match=r"symbolic link|not canonical"):
        _authorize(prepared, _ordinary())

    path.unlink()
    outside.unlink()
    path.write_bytes(original)
    path.chmod(0o600)
    alias = tmp_path / "authorization-hardlink.json"
    os.link(path, alias)
    with pytest.raises(UnsafePathError, match=r"singly linked|hard links"):
        TerraformApplyAuthorizationStore(prepared.paths, OPERATION_ID).read(
            expected_cluster_uuid=_checkpoint_cluster_uuid(prepared),
            expected_cluster_name="example",
        )


def test_ambiguous_replay_and_tampered_authorization_fail_closed(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)
    _authorize(prepared, _ordinary())
    path = _authorization_path(prepared)
    original = path.read_bytes()

    replay = terraform_apply_authorization_path(prepared.paths, _OTHER_OPERATION_ID)
    replay.write_bytes(original)
    replay.chmod(0o600)
    with pytest.raises(StatePersistenceError, match="identity conflicts"):
        TerraformApplyAuthorizationStore(prepared.paths, _OTHER_OPERATION_ID).read(
            expected_cluster_uuid=_checkpoint_cluster_uuid(prepared),
            expected_cluster_name="example",
        )

    duplicate = prepared.paths.terraform_plans / (
        f"{OPERATION_ID}.duplicate.terraform-apply-authorization.json"
    )
    shutil.copyfile(path, duplicate)
    duplicate.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _authorize(prepared, _ordinary())
    duplicate.unlink()

    document = json.loads(original)
    document["authorization_digest"] = _OTHER_DIGEST
    path.write_bytes(serialize_json(document))
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError, match="record digest conflicts"):
        _authorize(prepared, _ordinary())


def test_persistence_failure_leaves_no_authorization_or_journal_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    def fail_write(self, value, *, expected_digest):
        del self, value, expected_digest
        raise StatePersistenceError("injected authorization persistence failure")

    monkeypatch.setattr(AtomicJsonFile, "write", fail_write)
    with pytest.raises(StatePersistenceError, match="injected authorization"):
        _authorize(prepared, _ordinary())

    assert not _authorization_path(prepared).exists()
    assert journal_path.read_bytes() == journal_before


def test_authorization_api_has_no_apply_destroy_or_protected_input_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("authorization must not invoke a subprocess")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _authorize(prepared, _ordinary())
    parameters = inspect.signature(authorize_deploy_apply).parameters
    executable = tmp_path / "terraform"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    builder = TerraformCommandBuilder(executable, prepared.paths)

    assert tuple(parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "path",
        "plan",
        "checkpoint",
        "classification",
        "command",
        "variables",
        "environment",
        "prompt",
        "operator",
    ):
        assert forbidden not in parameters
    assert not hasattr(builder, "apply")
    assert not hasattr(builder, "destroy")
    assert report.apply_execution == "unavailable"
    assert report.state_backup == "unavailable"
