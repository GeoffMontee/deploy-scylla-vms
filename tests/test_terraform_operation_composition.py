import inspect
import json
import shutil
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from test_terraform_plan_checkpoint import (
    ADDRESS_MARKER,
    NOW,
    OPERATION_ID,
    SECRET_MARKER,
    _change,
    _paths,
    _plan_json,
    _prepare_foundation,
    _toolchain,
)

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import (
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json
from scylla_vms.state import StatePaths
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.operation_composition import (
    TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION,
    DeployPlanCompositionState,
    compose_deploy_plan_journal,
)
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    TerraformPlanCheckpointService,
    TerraformPlanCheckpointStore,
)

_OTHER_DIGEST = "sha256:" + "b" * 64


@dataclass(frozen=True, slots=True)
class _Prepared:
    paths: StatePaths
    plan_json: str


def _prepare(
    tmp_path: Path,
    *,
    resource_changes: list[dict[str, object]] | None = None,
    resource_drift: list[dict[str, object]] | None = None,
    write_state: bool = True,
) -> _Prepared:
    paths = _paths(tmp_path)
    plan_json = _plan_json(
        resource_changes=resource_changes
        if resource_changes is not None
        else [_change("oci_core_instance.created", ["create"])],
        resource_drift=resource_drift,
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        _prepare_foundation(tmp_path, paths, lock, write_state=write_state)
        TerraformPlanCheckpointService(paths).capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=lock,
        )
    return _Prepared(paths, plan_json)


def _compose(prepared: _Prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return compose_deploy_plan_journal(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
        )


def _read_journal(prepared: _Prepared):
    checkpoint = TerraformPlanCheckpointStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=_checkpoint(prepared).cluster_uuid,
        expected_cluster_name="example",
        expected_operation="deploy",
    )
    return OperationJournalStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=checkpoint.record.cluster_uuid,
        expected_cluster_name="example",
    )


def _checkpoint(prepared: _Prepared):
    value = json.loads(
        (
            prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
        ).read_text(encoding="utf-8")
    )
    return (
        TerraformPlanCheckpointStore(prepared.paths, OPERATION_ID)
        .read(
            expected_cluster_uuid=uuid.UUID(value["cluster_uuid"]),
            expected_cluster_name=value["cluster_name"],
            expected_operation=value["operation"],
        )
        .record
    )


def _rewrite_json(
    path: Path,
    mutate: Callable[[dict[str, object]], None],
    *,
    canonical: bool = True,
) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    if canonical:
        path.write_bytes(serialize_json(value))
    else:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def test_fresh_composition_appends_the_exact_plan_event_and_redacted_report(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        resource_changes=[
            _change("oci_core_instance.created", ["create"]),
            _change("oci_core_instance.updated", ["update"]),
        ],
    )
    checkpoint = _checkpoint(prepared)

    report = _compose(prepared)
    journal = _read_journal(prepared)
    projected = json.dumps(report.to_object(), sort_keys=True)
    persisted_journal = (prepared.paths.operations / f"{OPERATION_ID}.json").read_text(
        encoding="utf-8"
    )

    assert report.schema_version == (
        TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
    )
    assert report.state is DeployPlanCompositionState.CREATED
    assert report.checkpoint_schema_version == (
        TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    )
    assert report.review_schema_version == TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    assert report.journal_generation == 2
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.PLAN
    assert report.apply_authorization == "not-collected"
    assert report.execution_intent == "not-started"
    assert report.apply_execution == "unavailable"
    assert report.destructive_boundary == "not-crossed"
    assert journal.record.evidence == (
        CheckpointEvidence(
            OperationPhase.PLAN,
            EvidenceResult.VALIDATED,
            checkpoint.checkpoint_digest,
            "terraform-plan-reviewed",
        ),
    )
    assert report.to_object()["authorization"]["plan_approved"] is False
    assert report.to_object()["execution"]["apply_command_available"] is False
    for protected in (
        SECRET_MARKER,
        ADDRESS_MARKER,
        str(tmp_path),
        "oci_core_instance",
        "binary saved plan",
    ):
        assert protected not in projected
        assert protected not in persisted_journal


def test_checkpoint_only_prefix_survives_journal_failure_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    checkpoint_path = (
        prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    )
    checkpoint_before = checkpoint_path.read_bytes()
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("injected deploy PLAN journal write failure")

    monkeypatch.setattr(OperationJournalStore, "write", fail_write)
    with pytest.raises(StatePersistenceError, match="injected deploy PLAN"):
        _compose(prepared)

    assert checkpoint_path.read_bytes() == checkpoint_before
    assert journal_path.read_bytes() == journal_before

    monkeypatch.undo()
    recovered = _compose(prepared)
    assert recovered.state is DeployPlanCompositionState.CREATED
    assert _read_journal(prepared).record.generation == 2


def test_exact_reentry_reuses_without_journal_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    created = _compose(prepared)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise AssertionError("idempotent composition must not write")

    monkeypatch.setattr(OperationJournalStore, "write", fail_write)
    reused = _compose(prepared)

    assert reused.state is DeployPlanCompositionState.REUSED
    assert reused.journal_digest == created.journal_digest
    assert journal_path.read_bytes() == journal_before


@pytest.mark.parametrize(
    ("resource_changes", "resource_drift", "expected"),
    [
        (
            [_change("oci_core_instance.replaced", ["delete", "create"])],
            None,
            (True, False, False),
        ),
        (
            [_change("oci_core_instance.deleted", ["delete"])],
            None,
            (False, True, False),
        ),
        (
            [_change("oci_core_instance.created", ["create"])],
            [_change("oci_core_instance.drifted", ["update"])],
            (False, False, True),
        ),
    ],
)
def test_report_preserves_replacement_deletion_and_drift_classification(
    tmp_path: Path,
    resource_changes: list[dict[str, object]],
    resource_drift: list[dict[str, object]] | None,
    expected: tuple[bool, bool, bool],
) -> None:
    report = _compose(
        _prepare(
            tmp_path,
            resource_changes=resource_changes,
            resource_drift=resource_drift,
        )
    ).to_object()
    plan = report["plan"]

    assert (
        plan["has_replacements"],
        plan["has_deletions"],
        plan["has_drift"],
    ) == expected
    assert set(plan["scopes"]) == {
        "change",
        "deletion",
        "destructive",
        "drift",
        "replacement",
    }


@pytest.mark.parametrize(
    ("artifact", "mutate"),
    [
        (
            "checkpoint",
            lambda value: value.__setitem__("backend_kind", "unsupported-remote"),
        ),
        (
            "checkpoint",
            lambda value: value["summary"].__setitem__("terraform_version", "1.7.0"),
        ),
        (
            "checkpoint",
            lambda value: value.__setitem__("classification", "sensitive"),
        ),
        (
            "checkpoint",
            lambda value: value.__setitem__("operation", "redeploy"),
        ),
        (
            "checkpoint",
            lambda value: value.__setitem__(
                "operation_id", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            ),
        ),
        (
            "checkpoint",
            lambda value: value.__setitem__("cluster_name", "other"),
        ),
        (
            "checkpoint",
            lambda value: value.__setitem__(
                "cluster_uuid", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
            ),
        ),
    ],
)
def test_tampered_checkpoint_backend_toolchain_class_and_identity_fail_closed(
    tmp_path: Path,
    artifact: str,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    prepared = _prepare(tmp_path)
    assert artifact == "checkpoint"
    path = prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    _rewrite_json(path, mutate)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _compose(prepared)


@pytest.mark.parametrize(
    "path_name",
    ["cluster_metadata", "terraform_tfvars", "terraform_source_record"],
)
def test_current_desired_tfvars_and_source_artifact_drift_fail_closed(
    tmp_path: Path,
    path_name: str,
) -> None:
    prepared = _prepare(tmp_path)
    path = getattr(prepared.paths, path_name)
    _rewrite_json(path, lambda value: None, canonical=False)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _compose(prepared)


@pytest.mark.parametrize("artifact", ["state", "saved-plan"])
def test_current_state_and_saved_plan_drift_fail_closed(
    tmp_path: Path,
    artifact: str,
) -> None:
    prepared = _prepare(tmp_path)
    path = (
        prepared.paths.terraform_state
        if artifact == "state"
        else prepared.paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    )
    path.write_bytes(path.read_bytes() + b"\nchanged")
    path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _compose(prepared)


def test_journal_preimage_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    _rewrite_json(
        journal_path,
        lambda value: value.__setitem__("updated_at", "2026-09-18T20:00:01Z"),
    )

    with pytest.raises(StateConflictError, match="generation conflicts"):
        _compose(prepared)


@pytest.mark.parametrize(
    "journal_state",
    ["conflicting", "duplicate", "confirm", "execute", "terminal"],
)
def test_conflicting_duplicate_advanced_execution_and_terminal_history_refused(
    tmp_path: Path,
    journal_state: str,
) -> None:
    prepared = _prepare(tmp_path)
    checkpoint = _checkpoint(prepared)
    journal = _read_journal(prepared)
    exact = CheckpointEvidence(
        OperationPhase.PLAN,
        EvidenceResult.VALIDATED,
        checkpoint.checkpoint_digest,
        "terraform-plan-reviewed",
    )
    store = OperationJournalStore(prepared.paths, OPERATION_ID)
    if journal_state == "conflicting":
        candidate = journal.record.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            evidence=(
                CheckpointEvidence(
                    OperationPhase.PLAN,
                    EvidenceResult.VALIDATED,
                    _OTHER_DIGEST,
                    "terraform-plan-reviewed",
                ),
            ),
            clock=lambda: NOW,
        )
    elif journal_state == "confirm":
        candidate = journal.record.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.CONFIRM,
            evidence=(exact,),
            clock=lambda: NOW,
        )
    elif journal_state == "execute":
        candidate = journal.record.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.EXECUTE,
            evidence=(exact,),
            clock=lambda: NOW,
        )
    elif journal_state == "terminal":
        candidate = journal.record.transition(
            status=JournalStatus.FAILED,
            phase=OperationPhase.PLAN,
            evidence=(),
            clock=lambda: NOW,
        )
    else:
        path = prepared.paths.operations / f"{OPERATION_ID}.json"
        _rewrite_json(
            path,
            lambda value: value["evidence"].extend(
                [
                    exact.to_object(),
                    CheckpointEvidence(
                        OperationPhase.PLAN,
                        EvidenceResult.VALIDATED,
                        _OTHER_DIGEST,
                        "terraform-plan-conflict",
                    ).to_object(),
                ]
            ),
        )
        with pytest.raises(StatePersistenceError, match="phases must be unique"):
            _compose(prepared)
        return
    store.write(
        candidate,
        expected_generation=journal.record.generation,
        expected_digest=journal.digest,
    )

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _compose(prepared)


def test_absent_initial_terraform_state_is_bound_and_composed(tmp_path: Path) -> None:
    report = _compose(_prepare(tmp_path, write_state=False))

    assert report.state is DeployPlanCompositionState.CREATED
    assert report.journal_generation == 2


def test_missing_initial_journal_fails_without_recreating_it(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_path.unlink()

    with pytest.raises((StatePersistenceError, UnsafePathError)):
        _compose(prepared)

    assert not journal_path.exists()


def test_matching_lock_and_ambiguous_paths_are_required(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    unlocked = ClusterLock(prepared.paths, "deploy", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        compose_deploy_plan_journal(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            unlocked,
        )
    with (
        ClusterLock(prepared.paths, "redeploy", 0) as wrong,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        compose_deploy_plan_journal(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            wrong,
        )

    duplicate = prepared.paths.terraform_plans / (
        f"{OPERATION_ID}.duplicate.terraform-plan.json"
    )
    shutil.copyfile(
        prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json",
        duplicate,
    )
    duplicate.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _compose(prepared)


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlink support required")
def test_checkpoint_permissions_and_symlink_fail_closed(tmp_path: Path) -> None:
    permissions_root = tmp_path / "permissions"
    permissions_root.mkdir()
    permissions = _prepare(permissions_root)
    checkpoint_path = (
        permissions.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    )
    checkpoint_path.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        _compose(permissions)

    symlink_root = tmp_path / "symlink"
    symlink_root.mkdir()
    symlink = _prepare(symlink_root)
    checkpoint_path = (
        symlink.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    )
    outside = tmp_path / "outside-checkpoint.json"
    checkpoint_path.replace(outside)
    checkpoint_path.symlink_to(outside)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        _compose(symlink)


def test_composition_has_no_authorization_apply_or_tool_execution_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("composition must not invoke a subprocess")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _compose(prepared)
    parameters = inspect.signature(compose_deploy_plan_journal).parameters
    executable = tmp_path / "terraform"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    builder = TerraformCommandBuilder(executable, prepared.paths)

    for forbidden in (
        "operation_kind",
        "journal",
        "plan",
        "plan_json",
        "plan_bytes",
        "path",
        "command",
        "variables",
        "environment",
        "authorization",
        "status",
        "phase",
    ):
        assert forbidden not in parameters
    assert not hasattr(builder, "apply")
    assert not hasattr(builder, "destroy")
    assert report.apply_authorization == "not-collected"
    assert not any(
        "authorization" in path.name or "execution" in path.name
        for path in prepared.paths.operations.iterdir()
    )
