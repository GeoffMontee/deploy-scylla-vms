import inspect
import json
import os
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_ansible_operation_binding import _OPERATION_ID
from test_ansible_operation_coordinator import FakeCoordinatorRunner
from test_ansible_operation_lifecycle import _executables, _fresh_results
from test_ansible_operation_preparation import _prepare as _prepare_lifecycle_state
from test_check_jump_hosts import (
    FakeRunner,
    _prepared_state,
    _recap,
    _results,
    _run,
)

import scylla_vms.persistence as persistence_module
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.operation_context import OPERATION_CONTEXT_UNMODELED
from scylla_vms.ansible.operation_initiation import (
    ANSIBLE_OPERATION_INITIATION_REPORT_SCHEMA_VERSION,
    OperationInitiationState,
    initiate_check_jump_hosts_operation,
)
from scylla_vms.ansible.operation_lifecycle import (
    CheckJumpHostsLifecycleState,
    coordinate_check_jump_hosts_lifecycle,
)
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    ConfigurationError,
    ExitCode,
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
    OperationRecord,
    is_initial_plan_record,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import ClusterMetadataStore, digest_bytes
from scylla_vms.state import StatePaths, initialize_state_layout

_OTHER_OPERATION_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
_OTHER_CLUSTER_UUID = uuid.UUID("22222222-2222-4222-8222-222222222222")
_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-secret-value"


def _clock(second: int = 0) -> datetime:
    return datetime(2026, 9, 18, 18, 0, second, tzinfo=UTC)


def _request(paths: StatePaths, *extra: str, operation: str = "check-jump-hosts"):
    return parse_operation_request(
        [
            "--cluster-name",
            paths.cluster_root.name,
            "--state-dir",
            str(paths.state_root),
            operation,
            *extra,
        ],
        environ={},
    )


def _initiate(
    paths: StatePaths,
    request,
    *,
    operation_id: uuid.UUID = _OPERATION_ID,
):
    with ClusterLock(paths, "check-jump-hosts", 0) as lock:
        return initiate_check_jump_hosts_operation(
            paths.state_root,
            paths.cluster_root.name,
            operation_id,
            "check-jump-hosts",
            request,
            lock,
            clock=lambda: _clock(),
        )


def _journal(paths: StatePaths, operation_id: uuid.UUID = _OPERATION_ID):
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    return OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )


def _operation_bytes(paths: StatePaths) -> dict[str, bytes]:
    return {
        entry.name: entry.read_bytes()
        for entry in paths.operations.iterdir()
        if entry.is_file()
    }


def _prepared_at(path: Path):
    path.mkdir(mode=0o700)
    return _prepared_state(path)


def _second_cluster(paths: StatePaths) -> StatePaths:
    first = (
        ClusterMetadataStore(paths)
        .read(
            expected_cluster_name="example",
            expected_provider="oci",
        )
        .record
    )
    other = StatePaths.derive(paths.state_root, "other")
    initialize_state_layout(other)
    desired = replace(
        first.desired_spec,
        cluster_uuid=_OTHER_CLUSTER_UUID,
        cluster_name="other",
    )
    metadata = replace(
        first,
        cluster_uuid=_OTHER_CLUSTER_UUID,
        cluster_name="other",
        desired_spec=desired,
    )
    ClusterMetadataStore(other).write(
        metadata,
        expected_generation=0,
        expected_digest=None,
    )
    return other


def test_fresh_creation_owns_exact_initial_plan_shape_and_redacted_report(
    tmp_path: Path,
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = _request(paths, "--jump-host", "jump-host-1")

    report = _initiate(paths, request)
    stored = _journal(paths)

    assert report.schema_version == ANSIBLE_OPERATION_INITIATION_REPORT_SCHEMA_VERSION
    assert report.state is OperationInitiationState.CREATED
    assert report.operation_id == _OPERATION_ID
    assert report.selected_stable_ids == ("jump-host-1",)
    assert report.target_count == 1
    assert report.request_digest == normalized_operation_request_digest(request)
    assert report.journal_digest == stored.digest
    assert is_initial_plan_record(stored.record)
    assert stored.record.operation == "check-jump-hosts"
    assert stored.record.cluster_name == "example"
    assert stored.record.evidence == ()
    assert stored.record.created_at == stored.record.updated_at
    assert (paths.operations / f"{_OPERATION_ID}.json").stat().st_mode & 0o777 == 0o600

    encoded = json.dumps(report.to_object(), sort_keys=True)
    assert report.to_object()["operation"]["classification"] == "read-only"  # type: ignore[index]
    for forbidden in (
        "10.0.0.",
        "203.0.113.",
        "PRIVATE KEY",
        "environment",
        "inventory",
        "known_hosts",
        "route",
        _PRIVATE_PATH,
        _SECRET,
        str(paths.state_root),
    ):
        assert forbidden not in encoded


def test_exact_reentry_reuses_without_rewriting(tmp_path: Path) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = _request(paths, "--jump-host", "jump-host-1")
    first = _initiate(paths, request)
    before = _operation_bytes(paths)

    second = _initiate(paths, request)

    assert first.state is OperationInitiationState.CREATED
    assert second.state is OperationInitiationState.REUSED
    assert second.journal_digest == first.journal_digest
    assert _operation_bytes(paths) == before


def test_changed_request_target_and_existing_kind_fail_closed(tmp_path: Path) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    _initiate(paths, _request(paths))

    for changed in (
        _request(paths, "--jump-host", "jump-host-1"),
        _request(paths, "--connect-timeout-seconds", "3.5"),
    ):
        with pytest.raises(StateConflictError, match="UUID or request"):
            _initiate(paths, changed)

    paths2, _, _ = _prepared_at(tmp_path / "kind")
    metadata = ClusterMetadataStore(paths2).read(
        expected_cluster_name="example",
        expected_provider="oci",
    )
    pending = OperationRecord.create(
        operation_id=_OPERATION_ID,
        operation="show",
        cluster_uuid=metadata.record.cluster_uuid,
        cluster_name="example",
        request_digest=digest_bytes(b"other"),
        clock=lambda: _clock(),
    )
    OperationJournalStore(paths2, _OPERATION_ID).write(
        pending,
        expected_generation=0,
        expected_digest=None,
    )
    with pytest.raises(StateConflictError, match="UUID or request"):
        _initiate(paths2, _request(paths2))


def test_wrong_kind_returns_stable_blockers_before_writes(tmp_path: Path) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    show = _request(paths, operation="show")
    before = _operation_bytes(paths)

    with ClusterLock(paths, "check-jump-hosts", 0) as lock:
        report = initiate_check_jump_hosts_operation(
            paths.state_root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            show,
            lock,
        )
        direct = initiate_check_jump_hosts_operation(
            paths.state_root,
            "example",
            _OPERATION_ID,
            "show",
            show,
            lock,
        )

    for blocked in (report, direct):
        assert blocked.state is OperationInitiationState.BLOCKED
        assert blocked.blockers == (
            OPERATION_CONTEXT_UNMODELED,
            "operation-kind-conflict",
        )
    assert _operation_bytes(paths) == before


def test_cluster_identity_and_cross_cluster_uuid_replay_fail_closed(
    tmp_path: Path,
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = _request(paths)
    _initiate(paths, request)
    other = _second_cluster(paths)
    other_request = _request(other)

    with (
        ClusterLock(other, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="another cluster"),
    ):
        initiate_check_jump_hosts_operation(
            other.state_root,
            "other",
            _OPERATION_ID,
            "check-jump-hosts",
            other_request,
            lock,
        )

    with (
        ClusterLock(paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="identity conflicts"),
    ):
        initiate_check_jump_hosts_operation(
            paths.state_root,
            "example",
            _OTHER_OPERATION_ID,
            "check-jump-hosts",
            other_request,
            lock,
        )


def test_other_active_operation_blocks_but_terminal_history_does_not(
    tmp_path: Path,
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = _request(paths)
    _initiate(paths, request, operation_id=_OTHER_OPERATION_ID)

    report = _initiate(paths, request)
    assert report.state is OperationInitiationState.BLOCKED
    assert report.blockers == ("active-operation-conflict",)
    assert not (paths.operations / f"{_OPERATION_ID}.json").exists()

    active = _journal(paths, _OTHER_OPERATION_ID)
    failed = active.record.transition(
        status=JournalStatus.FAILED,
        phase=OperationPhase.PLAN,
        evidence=(),
        clock=lambda: _clock(1),
    )
    OperationJournalStore(paths, _OTHER_OPERATION_ID).write(
        failed,
        expected_generation=active.record.generation,
        expected_digest=active.digest,
    )
    assert _initiate(paths, request).state is OperationInitiationState.CREATED


@pytest.mark.parametrize("history", ["companion", "planned", "terminal", "pending"])
def test_companion_advanced_terminal_and_legacy_history_refuse_reuse(
    tmp_path: Path,
    history: str,
) -> None:
    paths, _, _ = _prepared_at(tmp_path / history)
    request = _request(paths)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name="example",
        expected_provider="oci",
    )
    if history == "companion":
        companion = OperationPlanBindingStore(paths, _OPERATION_ID).path
        companion.write_text("{}\n", encoding="utf-8")
        companion.chmod(0o600)
        match = "companion"
    else:
        initial = OperationRecord.create_initial_plan(
            operation_id=_OPERATION_ID,
            operation="check-jump-hosts",
            cluster_uuid=metadata.record.cluster_uuid,
            cluster_name="example",
            request_digest=normalized_operation_request_digest(request),
            clock=lambda: _clock(),
        )
        if history == "planned":
            record = initial.transition(
                status=JournalStatus.IN_PROGRESS,
                phase=OperationPhase.PLAN,
                evidence=(
                    CheckpointEvidence(
                        OperationPhase.PLAN,
                        EvidenceResult.VALIDATED,
                        digest_bytes(b"plan"),
                        "ansible-operation-plan-ready",
                    ),
                ),
                clock=lambda: _clock(1),
            )
        elif history == "terminal":
            record = OperationRecord(
                generation=1,
                operation_id=_OPERATION_ID,
                operation="check-jump-hosts",
                cluster_uuid=metadata.record.cluster_uuid,
                cluster_name="example",
                status=JournalStatus.SUCCEEDED,
                phase=OperationPhase.JOURNAL,
                created_at="2026-09-18T18:00:00Z",
                updated_at="2026-09-18T18:00:00Z",
                request_digest=normalized_operation_request_digest(request),
                resume_revalidation_digest=None,
                evidence=(
                    CheckpointEvidence(
                        OperationPhase.VERIFY,
                        EvidenceResult.COMPLETED,
                        digest_bytes(b"verified"),
                        "postconditions-healthy",
                    ),
                ),
            )
        else:
            record = OperationRecord.create(
                operation_id=_OPERATION_ID,
                operation="check-jump-hosts",
                cluster_uuid=metadata.record.cluster_uuid,
                cluster_name="example",
                request_digest=normalized_operation_request_digest(request),
                clock=lambda: _clock(),
            )
        store = OperationJournalStore(paths, _OPERATION_ID)
        if history == "planned":
            stored = store.write(
                initial,
                expected_generation=0,
                expected_digest=None,
            )
            store.write(
                record,
                expected_generation=stored.record.generation,
                expected_digest=stored.digest,
            )
        else:
            store.write(record, expected_generation=0, expected_digest=None)
        match = "UUID or request"

    with pytest.raises(StateConflictError, match=match):
        _initiate(paths, request)


def test_lock_type_operation_and_api_surface_are_narrow(tmp_path: Path) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = _request(paths)
    parameters = inspect.signature(initiate_check_jump_hosts_operation).parameters
    assert tuple(parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "operation_kind",
        "request",
        "lock",
        "clock",
    )
    for forbidden in (
        "journal",
        "path",
        "phase",
        "status",
        "event",
        "plan",
        "variables",
        "commands",
        "environment",
        "evidence",
    ):
        assert forbidden not in parameters

    unlocked = ClusterLock(paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        initiate_check_jump_hosts_operation(
            paths.state_root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            request,
            unlocked,
        )
    with (
        ClusterLock(paths, "show", 0) as wrong,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        initiate_check_jump_hosts_operation(
            paths.state_root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            request,
            wrong,
        )


def test_uninitialized_metadata_path_and_permission_guards(tmp_path: Path) -> None:
    root = tmp_path / "state"
    missing = StatePaths.derive(root, "example")
    initialize_state_layout(missing)
    request = _request(missing)
    with (
        ClusterLock(missing, "check-jump-hosts", 0) as lock,
        pytest.raises((UnsafePathError, StatePersistenceError)),
    ):
        initiate_check_jump_hosts_operation(
            root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            request,
            lock,
        )

    paths, _, _ = _prepared_at(tmp_path / "permissions")
    request = _request(paths)
    with ClusterLock(paths, "check-jump-hosts", 0) as lock:
        paths.operations.chmod(0o755)
        with pytest.raises(UnsafePathError, match="0700"):
            initiate_check_jump_hosts_operation(
                paths.state_root,
                "example",
                _OPERATION_ID,
                "check-jump-hosts",
                request,
                lock,
            )

    with pytest.raises(ConfigurationError):
        initiate_check_jump_hosts_operation(
            paths.state_root,
            "../example",
            _OPERATION_ID,
            "check-jump-hosts",
            request,
            ClusterLock(paths, "check-jump-hosts", 0),
        )


def test_symlink_and_ownership_guards_fail_before_journal_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _, _ = _prepared_at(tmp_path / "symlink")
    request = _request(paths)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    with ClusterLock(paths, "check-jump-hosts", 0) as lock:
        paths.operations.rmdir()
        paths.operations.symlink_to(outside, target_is_directory=True)
        with pytest.raises(UnsafePathError, match="symbolic link"):
            initiate_check_jump_hosts_operation(
                paths.state_root,
                "example",
                _OPERATION_ID,
                "check-jump-hosts",
                request,
                lock,
            )
    assert not (outside / f"{_OPERATION_ID}.json").exists()

    owned, _, _ = _prepared_at(tmp_path / "owner")
    owned_request = _request(owned)
    with ClusterLock(owned, "check-jump-hosts", 0) as lock:
        monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
        with pytest.raises(UnsafePathError, match="not owned"):
            initiate_check_jump_hosts_operation(
                owned.state_root,
                "example",
                _OPERATION_ID,
                "check-jump-hosts",
                owned_request,
                lock,
            )
    assert not (owned.operations / f"{_OPERATION_ID}.json").exists()


def test_atomic_publication_failure_leaves_no_journal_or_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = _request(paths)

    def fail_link(*args, **kwargs):
        raise OSError("injected publication failure")

    monkeypatch.setattr(persistence_module.os, "link", fail_link)
    with pytest.raises(StatePersistenceError, match="atomic state write failed"):
        _initiate(paths, request)

    assert not (paths.operations / f"{_OPERATION_ID}.json").exists()
    assert tuple(paths.operations.iterdir()) == ()


def test_later_conflict_does_not_roll_back_durable_initial_journal(
    tmp_path: Path,
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = _request(paths)
    _initiate(paths, request)
    before = _operation_bytes(paths)
    companion = OperationPlanBindingStore(paths, _OPERATION_ID).path
    companion.write_text("{}\n", encoding="utf-8")
    companion.chmod(0o600)

    with pytest.raises(StateConflictError, match="companion"):
        _initiate(paths, request)

    assert (paths.operations / f"{_OPERATION_ID}.json").read_bytes() == before[
        f"{_OPERATION_ID}.json"
    ]
    assert companion.exists()


def test_protected_inputs_are_rejected_before_journal_write(tmp_path: Path) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    request = parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(paths.state_root),
            "check-jump-hosts",
        ],
        environ={"DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN": _SECRET},
    )

    with pytest.raises(StateConflictError, match="protected-inputs-forbidden"):
        _initiate(paths, request)

    assert _operation_bytes(paths) == {}


def test_lifecycle_consumes_initiated_journal_with_fake_runner(tmp_path: Path) -> None:
    prepared = _prepare_lifecycle_state(tmp_path)
    (prepared.paths.operations / f"{_OPERATION_ID}.json").unlink()
    report = _initiate(prepared.paths, prepared.request)
    runner = FakeCoordinatorRunner(_fresh_results(prepared))

    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        lifecycle = coordinate_check_jump_hosts_lifecycle(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            prepared.request,
            lock,
            runner=runner,
            executables=_executables(tmp_path),
        )

    assert report.state is OperationInitiationState.CREATED
    assert lifecycle.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert _journal(prepared.paths).record.generation == 4


def test_existing_public_check_jump_hosts_remains_write_free(tmp_path: Path) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    before = _operation_bytes(paths)

    result, _, _ = _run(paths, FakeRunner(_results(inventory, _recap())))

    assert result == ExitCode.SUCCESS
    assert _operation_bytes(paths) == before
