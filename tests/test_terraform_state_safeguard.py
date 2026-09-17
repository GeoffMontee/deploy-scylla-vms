import inspect
import json
import os
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from test_terraform_apply_authorization import _authorize, _ordinary
from test_terraform_operation_composition import _compose, _prepare, _rewrite_json
from test_terraform_plan_checkpoint import (
    ADDRESS_MARKER,
    OPERATION_ID,
    SECRET_MARKER,
    STATE_LINEAGE,
)

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import AtomicJsonFile
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.state_safeguard import (
    TERRAFORM_STATE_SAFEGUARD_REPORT_SCHEMA_VERSION,
    TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION,
    TerraformStateBackupState,
    TerraformStateBackupStore,
    TerraformStateRecoveryPolicy,
    TerraformStateSafeguardResult,
    TerraformStateSafeguardStore,
    _state_identity_from_bytes,
    _StateSnapshot,
    safeguard_deploy_apply_state,
    terraform_state_backup_path,
    terraform_state_safeguard_path,
)

_OTHER_DIGEST = "sha256:" + "e" * 64


def _safeguard(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return safeguard_deploy_apply_state(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
        )


def _authorized(tmp_path: Path, *, write_state: bool = True):
    prepared = _prepare(tmp_path, write_state=write_state)
    _compose(prepared)
    _authorize(prepared, _ordinary())
    return prepared


def test_existing_state_is_backed_up_byte_for_byte_and_redacted(
    tmp_path: Path,
) -> None:
    prepared = _authorized(tmp_path)
    state_bytes = prepared.paths.terraform_state.read_bytes()
    report = _safeguard(prepared)
    backup_path = terraform_state_backup_path(prepared.paths, OPERATION_ID)
    safeguard_path = terraform_state_safeguard_path(prepared.paths, OPERATION_ID)
    persisted = safeguard_path.read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)

    assert report.schema_version == TERRAFORM_STATE_SAFEGUARD_REPORT_SCHEMA_VERSION
    assert report.safeguard_schema_version == TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
    assert report.result is TerraformStateSafeguardResult.CREATED
    assert report.backup_state is TerraformStateBackupState.CREATED
    assert report.recovery_policy is (
        TerraformStateRecoveryPolicy.RESTORE_EXACT_BACKUP_BEFORE_REPLAN
    )
    assert report.manual_recovery_available is True
    assert report.authorization_consumption == "unconsumed"
    assert report.execution_intent == "not-started"
    assert report.apply_execution == "unavailable"
    assert report.destructive_boundary == "not-crossed"
    assert backup_path.read_bytes() == state_bytes
    assert backup_path.stat().st_mode & 0o777 == 0o600
    assert safeguard_path.stat().st_mode & 0o777 == 0o600
    assert report.backup_digest == report.state_identity.state_digest
    assert report.backup_size_bytes == len(state_bytes)
    assert report.to_object()["execution"]["apply_command_available"] is False
    for protected in (
        SECRET_MARKER,
        ADDRESS_MARKER,
        STATE_LINEAGE,
        str(tmp_path),
        "resources",
        "instances",
        "attributes",
    ):
        assert protected not in persisted
        assert protected not in projected


def test_absent_initial_state_persists_proof_without_fake_backup(
    tmp_path: Path,
) -> None:
    prepared = _authorized(tmp_path, write_state=False)

    report = _safeguard(prepared)
    stored = TerraformStateSafeguardStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=_cluster_uuid(prepared),
        expected_cluster_name="example",
    )

    assert report.result is TerraformStateSafeguardResult.CREATED
    assert report.backup_state is TerraformStateBackupState.NOT_REQUIRED
    assert report.state_identity.presence.value == "absent"
    assert report.recovery_policy is (
        TerraformStateRecoveryPolicy.VERIFIED_ABSENT_INITIAL_STATE
    )
    assert report.backup_digest is None
    assert report.backup_size_bytes is None
    assert report.manual_recovery_available is False
    assert stored.record.absent_proof_digest is not None
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()
    assert not prepared.paths.terraform_state.exists()


def test_absent_state_appearance_and_exact_reentry_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appeared_root = tmp_path / "appeared"
    appeared_root.mkdir(mode=0o700)
    appeared = _authorized(appeared_root, write_state=False)
    appeared.paths.terraform_state.write_text(
        json.dumps(
            {
                "lineage": STATE_LINEAGE,
                "resources": [],
                "serial": 0,
                "terraform_version": "1.6.6",
                "version": 4,
            }
        ),
        encoding="utf-8",
    )
    appeared.paths.terraform_state.chmod(0o600)
    with pytest.raises(StateConflictError, match="stale or changed"):
        _safeguard(appeared)
    assert not terraform_state_safeguard_path(appeared.paths, OPERATION_ID).exists()

    reused_root = tmp_path / "reused"
    reused_root.mkdir(mode=0o700)
    reused = _authorized(reused_root, write_state=False)
    created = _safeguard(reused)
    record_path = terraform_state_safeguard_path(reused.paths, OPERATION_ID)
    before = record_path.read_bytes()

    def fail_json(self, value, *, expected_digest):
        del self, value, expected_digest
        raise AssertionError("absent-state exact reentry must not write")

    monkeypatch.setattr(AtomicJsonFile, "write", fail_json)
    report = _safeguard(reused)
    assert created.result is TerraformStateSafeguardResult.CREATED
    assert report.result is TerraformStateSafeguardResult.REUSED
    assert record_path.read_bytes() == before


def test_absent_state_refuses_canonical_or_unexpected_backend_metadata(
    tmp_path: Path,
) -> None:
    backup_root = tmp_path / "canonical-backup"
    backup_root.mkdir(mode=0o700)
    canonical_backup = _authorized(backup_root, write_state=False)
    canonical_backup.paths.terraform_state_backup.write_text(
        "not-a-state-projection", encoding="utf-8"
    )
    canonical_backup.paths.terraform_state_backup.chmod(0o600)
    with pytest.raises(StateConflictError, match="canonical backup metadata"):
        _safeguard(canonical_backup)

    unexpected_root = tmp_path / "unexpected"
    unexpected_root.mkdir(mode=0o700)
    unexpected = _authorized(unexpected_root, write_state=False)
    conflicting = unexpected.paths.cluster_root / "terraform.tfstate"
    conflicting.write_text("not-read", encoding="utf-8")
    conflicting.chmod(0o600)
    with pytest.raises(StateConflictError, match="unexpected Terraform state metadata"):
        _safeguard(unexpected)


def test_no_change_plan_reports_not_required_without_any_companion(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path, resource_changes=[])
    _compose(prepared)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    before = journal_path.read_bytes()

    report = _safeguard(prepared)

    assert report.result is TerraformStateSafeguardResult.NOT_REQUIRED
    assert report.backup_state is TerraformStateBackupState.NOT_REQUIRED
    assert report.authorization_digest is None
    assert report.authorization_state.value == "not-required"
    assert report.authorization_consumption == "not-required"
    assert report.apply_required is False
    assert report.safeguard_digest is None
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()
    assert not terraform_state_safeguard_path(prepared.paths, OPERATION_ID).exists()
    assert journal_path.read_bytes() == before


def test_apply_required_plan_requires_valid_unconsumed_authorization(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    _compose(prepared)
    with pytest.raises(StateConflictError, match="requires exact unconsumed"):
        _safeguard(prepared)

    _authorize(prepared, _ordinary())
    authorization = (
        prepared.paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-authorization.json"
    )
    _rewrite_json(
        authorization,
        lambda value: value.__setitem__("authorization_digest", _OTHER_DIGEST),
    )
    with pytest.raises(StatePersistenceError, match="record digest conflicts"):
        _safeguard(prepared)
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()
    assert not terraform_state_safeguard_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize("field", ["lineage", "serial", "digest"])
def test_state_identity_drift_fails_before_backup(tmp_path: Path, field: str) -> None:
    prepared = _authorized(tmp_path)
    value = json.loads(prepared.paths.terraform_state.read_text(encoding="utf-8"))
    if field == "lineage":
        value["lineage"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    elif field == "serial":
        value["serial"] += 1
    else:
        value["resources"].append({"mode": "managed"})
    prepared.paths.terraform_state.write_text(
        json.dumps(value, sort_keys=True), encoding="utf-8"
    )
    prepared.paths.terraform_state.chmod(0o600)

    with pytest.raises(StateConflictError, match="stale or changed"):
        _safeguard(prepared)
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()


def test_concurrent_state_replacement_is_detected_before_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _authorized(tmp_path)
    original_ensure = _StateSnapshot.ensure_current
    calls = 0

    def replace_before_backup(self):
        nonlocal calls
        calls += 1
        if calls == 2:
            replacement = prepared.paths.terraform / "replacement.tfstate"
            replacement.write_bytes(prepared.paths.terraform_state.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, prepared.paths.terraform_state)
        return original_ensure(self)

    monkeypatch.setattr(_StateSnapshot, "ensure_current", replace_before_backup)
    with pytest.raises(UnsafePathError, match="changed during safeguard"):
        _safeguard(prepared)
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()
    assert not terraform_state_safeguard_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions", "size"])
def test_unsafe_canonical_state_is_refused(tmp_path: Path, kind: str) -> None:
    prepared = _authorized(tmp_path)
    state_path = prepared.paths.terraform_state
    if kind == "symlink":
        outside = tmp_path / "outside.tfstate"
        state_path.replace(outside)
        state_path.symlink_to(outside)
    elif kind == "hardlink":
        os.link(state_path, tmp_path / "state-hardlink")
    elif kind == "permissions":
        state_path.chmod(0o644)
    else:
        with state_path.open("ab") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        state_path.chmod(0o600)

    with pytest.raises((StatePersistenceError, UnsafePathError)):
        _safeguard(prepared)
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()


def test_unexpected_state_owner_and_noncanonical_store_paths_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _authorized(tmp_path)
    monkeypatch.setattr(
        "scylla_vms.state.os.geteuid",
        lambda: prepared.paths.terraform_state.stat().st_uid + 1,
    )
    with pytest.raises(UnsafePathError, match=r"not owned|unexpected owner"):
        _safeguard(prepared)
    monkeypatch.undo()

    forged = replace(
        prepared.paths,
        terraform_backups=tmp_path / "outside-backups",
    )
    with pytest.raises(UnsafePathError, match="not canonical"):
        TerraformStateBackupStore(forged, OPERATION_ID)


def test_backup_only_prefix_recovers_without_rewriting_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _authorized(tmp_path)
    backup_path = terraform_state_backup_path(prepared.paths, OPERATION_ID)
    safeguard_path = terraform_state_safeguard_path(prepared.paths, OPERATION_ID)

    def fail_record(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError("injected safeguard record write failure")

    monkeypatch.setattr(TerraformStateSafeguardStore, "write_locked", fail_record)
    with pytest.raises(StatePersistenceError, match="injected safeguard record"):
        _safeguard(prepared)
    backup_before = backup_path.read_bytes()
    assert not safeguard_path.exists()

    monkeypatch.undo()
    report = _safeguard(prepared)
    assert report.result is TerraformStateSafeguardResult.CREATED
    assert report.backup_state is TerraformStateBackupState.REUSED
    assert report.recovered_backup_prefix is True
    assert backup_path.read_bytes() == backup_before


def test_record_without_required_backup_and_conflicting_orphan_fail_closed(
    tmp_path: Path,
) -> None:
    prepared = _authorized(tmp_path)
    _safeguard(prepared)
    backup_path = terraform_state_backup_path(prepared.paths, OPERATION_ID)
    backup_path.unlink()
    with pytest.raises(StateConflictError, match="without its required backup"):
        _safeguard(prepared)

    other_root = tmp_path / "other"
    other_root.mkdir(mode=0o700)
    other = _authorized(other_root)
    orphan = terraform_state_backup_path(other.paths, OPERATION_ID)
    orphan.write_bytes(b"conflicting orphan backup")
    orphan.chmod(0o600)
    with pytest.raises(StateConflictError, match="backup conflicts"):
        _safeguard(other)
    assert not terraform_state_safeguard_path(other.paths, OPERATION_ID).exists()


def test_backup_write_failure_leaves_no_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _authorized(tmp_path)

    def fail_backup(self, raw, *, lock):
        del self, raw, lock
        raise StatePersistenceError("injected backup write failure")

    monkeypatch.setattr(TerraformStateBackupStore, "write_locked", fail_backup)
    with pytest.raises(StatePersistenceError, match="injected backup"):
        _safeguard(prepared)
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()
    assert not terraform_state_safeguard_path(prepared.paths, OPERATION_ID).exists()


def test_exact_reentry_reuses_without_any_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _authorized(tmp_path)
    created = _safeguard(prepared)
    backup_path = terraform_state_backup_path(prepared.paths, OPERATION_ID)
    safeguard_path = terraform_state_safeguard_path(prepared.paths, OPERATION_ID)
    backup_before = backup_path.read_bytes()
    safeguard_before = safeguard_path.read_bytes()

    def fail_backup(self, raw, *, lock):
        del self, raw, lock
        raise AssertionError("idempotent safeguard must not write backup")

    def fail_json(self, value, *, expected_digest):
        del self, value, expected_digest
        raise AssertionError("idempotent safeguard must not write record")

    monkeypatch.setattr(TerraformStateBackupStore, "write_locked", fail_backup)
    monkeypatch.setattr(AtomicJsonFile, "write", fail_json)
    reused = _safeguard(prepared)

    assert reused.result is TerraformStateSafeguardResult.REUSED
    assert reused.backup_state is TerraformStateBackupState.REUSED
    assert reused.safeguard_digest == created.safeguard_digest
    assert backup_path.read_bytes() == backup_before
    assert safeguard_path.read_bytes() == safeguard_before


@pytest.mark.parametrize(
    "artifact",
    [
        "saved-plan",
        "checkpoint",
        "journal",
        "source-record",
        "source-body",
        "tfvars",
        "backend",
        "toolchain",
        "authorization",
    ],
)
def test_bound_artifact_drift_after_safeguard_fails_closed(
    tmp_path: Path, artifact: str
) -> None:
    prepared = _authorized(tmp_path)
    _safeguard(prepared)
    checkpoint = prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    if artifact == "saved-plan":
        path = prepared.paths.terraform_plans / f"{OPERATION_ID}.tfplan"
        path.write_bytes(path.read_bytes() + b"tampered")
        path.chmod(0o600)
    elif artifact == "checkpoint":
        _rewrite_json(
            checkpoint,
            lambda value: value.__setitem__("plan_json_digest", _OTHER_DIGEST),
        )
    elif artifact == "journal":
        path = prepared.paths.operations / f"{OPERATION_ID}.json"
        _rewrite_json(path, lambda value: value.__setitem__("generation", 3))
    elif artifact == "source-record":
        _rewrite_json(
            prepared.paths.terraform_source_record,
            lambda value: None,
            canonical=False,
        )
    elif artifact == "source-body":
        path = prepared.paths.terraform_work / "main.tf"
        path.write_bytes(path.read_bytes() + b"\n# drift\n")
        path.chmod(0o600)
    elif artifact == "tfvars":
        _rewrite_json(
            prepared.paths.terraform_tfvars,
            lambda value: None,
            canonical=False,
        )
    elif artifact == "backend":
        path = prepared.paths.terraform_work / "terraform.tfstate"
        path.write_text("{}", encoding="utf-8")
        path.chmod(0o600)
    elif artifact == "toolchain":
        _rewrite_json(
            checkpoint,
            lambda value: value["summary"].__setitem__("terraform_version", "1.7.0"),
        )
    else:
        path = (
            prepared.paths.terraform_plans
            / f"{OPERATION_ID}.terraform-apply-authorization.json"
        )
        _rewrite_json(path, lambda value: None, canonical=False)

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _safeguard(prepared)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions"])
def test_unsafe_existing_backup_is_refused(tmp_path: Path, kind: str) -> None:
    prepared = _authorized(tmp_path)
    _safeguard(prepared)
    backup = terraform_state_backup_path(prepared.paths, OPERATION_ID)
    if kind == "symlink":
        outside = tmp_path / "outside-backup"
        backup.replace(outside)
        backup.symlink_to(outside)
    elif kind == "hardlink":
        os.link(backup, tmp_path / "backup-hardlink")
    else:
        backup.chmod(0o644)

    with pytest.raises(UnsafePathError):
        _safeguard(prepared)


def test_api_is_lock_bound_subprocess_free_and_has_no_apply_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _authorized(tmp_path)

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("state safeguard must not invoke a subprocess")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    unlocked = ClusterLock(prepared.paths, "deploy", 0)
    with pytest.raises(StateLockError, match="acquired"):
        safeguard_deploy_apply_state(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            unlocked,
        )
    report = _safeguard(prepared)
    parameters = inspect.signature(safeguard_deploy_apply_state).parameters
    executable = tmp_path / "terraform"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    builder = TerraformCommandBuilder(executable, prepared.paths)

    assert tuple(parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    assert not hasattr(builder, "apply")
    assert not hasattr(builder, "destroy")
    assert report.apply_execution == "unavailable"
    assert report.authorization_consumption == "unconsumed"


def test_state_identity_parser_never_decodes_resource_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _authorized(tmp_path)
    raw = prepared.paths.terraform_state.read_bytes()
    original_loads = json.loads
    decoded_fragments: list[str] = []

    def record_decoded_fragment(value, *args, **kwargs):
        if isinstance(value, str):
            decoded_fragments.append(value)
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(
        "scylla_vms.terraform.state_safeguard.json.loads",
        record_decoded_fragment,
    )
    identity = _state_identity_from_bytes(raw)

    assert identity.state_digest is not None
    assert SECRET_MARKER not in "\n".join(decoded_fragments)
    assert all(len(fragment) < 128 for fragment in decoded_fragments)


def _cluster_uuid(prepared) -> uuid.UUID:
    cluster_uuid = json.loads(
        (
            prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
        ).read_text(encoding="utf-8")
    )["cluster_uuid"]
    return uuid.UUID(cluster_uuid)
