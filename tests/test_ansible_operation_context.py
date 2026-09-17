import json
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_operation_coordinator import (
    FakeCoordinatorRunner,
    PreparedCoordinator,
    _clock,
    _coordinate,
    _prepare,
    _results,
)

from scylla_vms.ansible.operation_binding import OperationPlanBindingStore
from scylla_vms.ansible.operation_context import (
    ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION,
    OPERATION_CONTEXT_PROTECTED_INPUTS,
    OPERATION_CONTEXT_UNMODELED,
    OperationContext,
    OperationContextStore,
    build_operation_context,
    operation_context_id_from_filename,
    operation_context_path,
    reconstruct_operation_context,
    safe_intent_context_digest,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock, ClusterReadLock
from scylla_vms.operations import get_operation
from scylla_vms.persistence import serialize_json
from scylla_vms.secrets import SecretInputs

_OPERATION_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


def _custom_prepared(tmp_path: Path) -> PreparedCoordinator:
    return _prepare(
        tmp_path,
        request_arguments=(
            "--jump-host",
            "jump-host-1",
            "--destination",
            "scylla",
            "--depth",
            "route",
            "--destination-check",
            "scylla=9042",
            "--connect-timeout-seconds",
            "2.5",
            "--check-timeout-seconds",
            "45",
        ),
    )


def test_context_round_trip_reconstructs_request_and_ephemeral_variables(
    tmp_path: Path,
) -> None:
    prepared = _custom_prepared(tmp_path)
    store = OperationContextStore(prepared.paths, _OPERATION_ID)
    with ClusterReadLock(prepared.paths, 0) as lock:
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name="example",
            expected_operation="check-jump-hosts",
        )

    reconstructed = reconstruct_operation_context(
        prepared.paths,
        stored,
        prepared.binding,
        prepared.inventory,
    )

    assert reconstructed.request == prepared.request
    assert reconstructed.active_conditions == ()
    assert len(reconstructed.intents) == len(prepared.plan.steps)
    assert tuple(intent.sequence for intent in reconstructed.intents) == tuple(
        step.sequence for step in prepared.plan.steps
    )
    assert tuple(intent.limit for intent in reconstructed.intents) == tuple(
        step.limit for step in prepared.plan.steps
    )
    assert reconstructed.intents[1].variables[
        "deploy_scylla_vms_destination_probes"
    ] == [
        {
            "address": "10.0.3.10",
            "jump_host_id": "jump-host-1",
            "port": 9042,
            "role": "scylla",
            "target_logical_id": "scylla-ad-1-1",
        }
    ]

    persisted = store.path.read_text(encoding="utf-8")
    assert ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION in persisted
    for forbidden in (
        "10.0.0.10",
        "10.0.3.10",
        "203.0.113.10",
        "ocid1.instance",
        str(prepared.paths.state_root),
        "ansible-playbook",
        "environment",
        "password",
        "private_key",
        "target_address",
    ):
        assert forbidden not in persisted
    public = stored.record.to_public_object()
    assert "values" not in public
    assert public["reconstruction"] == {
        "state": "reconstructable",
        "target_count": 1,
        "values_schema_version": (
            "deploy-scylla-vms.ansible-operation-context.check-jump-hosts/v1"
        ),
    }
    assert "jump-host-1" not in str(public)


@pytest.mark.parametrize(
    "case",
    (
        "unknown-top-level",
        "unknown-value",
        "integer-float-coercion",
        "string-integer-coercion",
        "timeout-over-bound",
        "nonfinite-timeout",
        "duplicate-destination",
        "duplicate-check",
        "boolean-port-coercion",
        "unknown-enum",
        "address-stable-id",
        "path-stable-id",
        "oversized-scalar",
        "unknown-operation",
        "command-field",
        "environment-field",
        "secret-field",
    ),
)
def test_context_rejects_unknown_unsafe_coerced_and_unbounded_fields(
    tmp_path: Path,
    case: str,
) -> None:
    prepared = _custom_prepared(tmp_path)
    document = json.loads(
        OperationContextStore(prepared.paths, _OPERATION_ID).path.read_text(
            encoding="utf-8"
        )
    )
    values = document["values"]
    if case == "unknown-top-level":
        document["unknown"] = True
    elif case == "unknown-value":
        values["alias"] = "bastion"
    elif case == "integer-float-coercion":
        values["connect_timeout_seconds"] = 2
    elif case == "string-integer-coercion":
        values["check_timeout_seconds"] = "45"
    elif case == "timeout-over-bound":
        values["check_timeout_seconds"] = 86_401
    elif case == "nonfinite-timeout":
        values["connect_timeout_seconds"] = float("inf")
    elif case == "duplicate-destination":
        values["destinations"] = ["scylla", "scylla"]
    elif case == "duplicate-check":
        values["destination_checks"] = [
            {"port": 9042, "role": "scylla"},
            {"port": 9042, "role": "scylla"},
        ]
    elif case == "boolean-port-coercion":
        values["destination_checks"] = [{"port": True, "role": "scylla"}]
    elif case == "unknown-enum":
        values["depth"] = "private"
    elif case == "address-stable-id":
        values["jump_hosts"] = ["10.0.0.10"]
    elif case == "path-stable-id":
        values["jump_hosts"] = ["/private/operator/id_ed25519"]
    elif case == "oversized-scalar":
        values["jump_hosts"] = ["a" * 129]
    elif case == "unknown-operation":
        document["operation"] = "future-operation"
    else:
        document[
            {
                "command-field": "command",
                "environment-field": "environment",
                "secret-field": "password",
            }[case]
        ] = "obviously-fake-forbidden-value"

    with pytest.raises((StateConflictError, StatePersistenceError)):
        OperationContext.from_object(document)


def test_context_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    prepared = _custom_prepared(tmp_path)
    store = OperationContextStore(prepared.paths, _OPERATION_ID)
    document = store.path.read_text(encoding="utf-8").replace(
        '"generation":1,', '"generation":1,"generation":1,', 1
    )
    store.path.write_text(document, encoding="utf-8")
    store.path.chmod(0o600)

    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(StatePersistenceError, match="duplicate field"),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name="example",
        )


def test_build_context_blocks_unmodeled_operations_and_protected_inputs(
    tmp_path: Path,
) -> None:
    prepared = _custom_prepared(tmp_path)

    with pytest.raises(StateConflictError, match=OPERATION_CONTEXT_UNMODELED):
        build_operation_context(
            prepared.metadata.record,
            replace(prepared.request, operation=get_operation("deploy")),
            _OPERATION_ID,
            prepared.plan,
            prepared.binding,
            clock=lambda: _clock(4),
        )

    request_with_secret = replace(
        prepared.request,
        secrets=SecretInputs.from_environment(
            {"DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN": "obviously-fake-secret"}
        ),
    )
    with pytest.raises(StateConflictError, match=OPERATION_CONTEXT_PROTECTED_INPUTS):
        build_operation_context(
            prepared.metadata.record,
            request_with_secret,
            _OPERATION_ID,
            prepared.plan,
            prepared.binding,
            clock=lambda: _clock(4),
        )


def test_context_store_requires_canonical_operation_lock_and_path(
    tmp_path: Path,
) -> None:
    prepared = _custom_prepared(tmp_path)
    store = OperationContextStore(prepared.paths, _OPERATION_ID)

    with pytest.raises(StateLockError, match="acquired cluster lock"):
        store.read_locked(
            object(),
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name="example",
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError, match="lock for the matching operation"),
    ):
        store.write_locked(
            prepared.operation_context.record,
            expected_generation=1,
            expected_digest=prepared.operation_context.digest,
            lock=wrong_lock,
        )
    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(UnsafePathError, match="not canonical"):
        OperationContextStore(forged, _OPERATION_ID)
    with pytest.raises(StatePersistenceError, match="must be a UUID"):
        OperationContextStore(prepared.paths, "not-a-uuid")  # type: ignore[arg-type]
    with pytest.raises(StatePersistenceError, match="must be sorted"):
        replace(
            prepared.operation_context.record,
            selected_stable_ids=("jump-host-2", "jump-host-1"),
        )


def test_context_path_helpers_are_exact_and_traversal_free(tmp_path: Path) -> None:
    prepared = _custom_prepared(tmp_path)
    expected = prepared.paths.operations / (
        f"{_OPERATION_ID}.ansible-operation-context.json"
    )
    assert operation_context_path(prepared.paths, _OPERATION_ID) == expected
    assert operation_context_id_from_filename(expected.name) == _OPERATION_ID
    assert (
        operation_context_id_from_filename(
            f"../{_OPERATION_ID}.ansible-operation-context.json"
        )
        is None
    )
    assert (
        operation_context_id_from_filename(
            f"{str(_OPERATION_ID).upper()}.ansible-operation-context.json"
        )
        is None
    )
    assert operation_context_id_from_filename("other.json") is None


@pytest.mark.parametrize("unsafe_kind", ("permissions", "symlink"))
def test_context_store_rejects_unsafe_files(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    prepared = _custom_prepared(tmp_path)
    store = OperationContextStore(prepared.paths, _OPERATION_ID)
    if unsafe_kind == "permissions":
        store.path.chmod(0o644)
    else:
        content = store.path.read_bytes()
        outside = tmp_path / "outside-context.json"
        outside.write_bytes(content)
        outside.chmod(0o600)
        store.path.unlink()
        store.path.symlink_to(outside)

    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises((StatePersistenceError, UnsafePathError)),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name="example",
        )


def test_context_store_is_idempotent_and_semantically_immutable(
    tmp_path: Path,
) -> None:
    prepared = _custom_prepared(tmp_path)
    store = OperationContextStore(prepared.paths, _OPERATION_ID)
    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        unchanged = store.write_locked(
            prepared.operation_context.record,
            expected_generation=1,
            expected_digest=prepared.operation_context.digest,
            lock=lock,
        )
        assert unchanged == prepared.operation_context

        changed_values = replace(
            prepared.operation_context.record.values,
            check_timeout_seconds=46,
        )
        changed = replace(
            prepared.operation_context.record,
            values=changed_values,
            intent_context_digest=safe_intent_context_digest(
                "check-jump-hosts",
                prepared.operation_context.record.selected_stable_ids,
                changed_values,
            ),
        )
        with pytest.raises(StateConflictError, match="request digest drifted"):
            store.write_locked(
                changed,
                expected_generation=1,
                expected_digest=prepared.operation_context.digest,
                lock=lock,
            )
        with pytest.raises(StatePersistenceError, match="concurrently"):
            store.write_locked(
                prepared.operation_context.record,
                expected_generation=1,
                expected_digest="sha256:" + "c" * 64,
                lock=lock,
            )


def test_context_creation_refuses_late_or_missing_binding(tmp_path: Path) -> None:
    prepared = _custom_prepared(tmp_path)
    store = OperationContextStore(prepared.paths, _OPERATION_ID)
    store.path.unlink()
    execution_path = (
        prepared.paths.operations / f"{_OPERATION_ID}.ansible-operation-execution.json"
    )
    execution_path.write_text("{}\n", encoding="utf-8")
    execution_path.chmod(0o600)
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="must precede authorization"),
    ):
        store.write_locked(
            prepared.operation_context.record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )

    execution_path.unlink()
    OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path.unlink()
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(UnsafePathError, match="does not exist"),
    ):
        store.write_locked(
            prepared.operation_context.record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )


def test_context_atomic_write_failure_leaves_no_record(
    tmp_path: Path,
) -> None:
    prepared = _custom_prepared(tmp_path)
    regular_store = OperationContextStore(prepared.paths, _OPERATION_ID)
    regular_store.path.unlink()
    temporary = regular_store.path.with_name(f".{regular_store.path.name}.injected.tmp")
    temporary.write_text("injected collision\n", encoding="utf-8")
    temporary.chmod(0o600)
    store = OperationContextStore(
        prepared.paths,
        _OPERATION_ID,
        token_factory=lambda: "injected",
    )
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StatePersistenceError, match="temporary state file"),
    ):
        store.write_locked(
            prepared.operation_context.record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    assert not store.path.exists()
    assert temporary.read_text(encoding="utf-8") == "injected collision\n"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("request_digest", "sha256:" + "c" * 64),
        ("plan_digest", "sha256:" + "c" * 64),
        ("binding_digest", "sha256:" + "c" * 64),
    ),
)
def test_context_binding_drift_is_rejected(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    prepared = _custom_prepared(tmp_path)
    if field == "request_digest":
        changed = replace(prepared.operation_context.record, request_digest=value)
    elif field == "plan_digest":
        changed = replace(prepared.operation_context.record, plan_digest=value)
    else:
        changed = replace(prepared.operation_context.record, binding_digest=value)
    store = OperationContextStore(prepared.paths, _OPERATION_ID)
    store.path.write_bytes(serialize_json(changed.to_object()))
    store.path.chmod(0o600)

    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(StateConflictError, match="binding drifted"),
    ):
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name="example",
        )
        reconstruct_operation_context(
            prepared.paths,
            stored,
            prepared.binding,
            prepared.inventory,
        )


def test_self_consistent_context_tamper_refuses_before_tool_probe(
    tmp_path: Path,
) -> None:
    prepared = _custom_prepared(tmp_path)
    changed_values = replace(
        prepared.operation_context.record.values,
        check_timeout_seconds=46,
    )
    changed = replace(
        prepared.operation_context.record,
        values=changed_values,
        intent_context_digest=safe_intent_context_digest(
            "check-jump-hosts",
            prepared.operation_context.record.selected_stable_ids,
            changed_values,
        ),
    )
    store = OperationContextStore(prepared.paths, _OPERATION_ID)
    store.path.write_bytes(serialize_json(changed.to_object()))
    store.path.chmod(0o600)
    runner = FakeCoordinatorRunner(_results(prepared))

    with pytest.raises(StateConflictError, match="request digest drifted"):
        _coordinate(prepared, runner)

    assert runner.specs == []
