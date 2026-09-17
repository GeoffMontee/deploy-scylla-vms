import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_operation_binding import _OPERATION_ID
from test_ansible_operation_coordinator import (
    FakeCoordinatorRunner,
    PreparedCoordinator,
    _coordinate,
    _intents_for_request,
    _prepare,
    _results,
)
from test_ansible_operation_orchestrator import _orchestrate, _successful_results
from test_check_jump_hosts import _tcp_recap

from scylla_vms.ansible.operation_evidence import (
    ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION,
    CONNECTIVITY_PROJECTION_SCHEMA_VERSION,
    INVENTORY_PREFLIGHT_PROJECTION_SCHEMA_VERSION,
    ConnectivityHostProjection,
    ConnectivityProjection,
    DestinationPairProjection,
    InventoryPreflightProjection,
    InventoryPreflightStatus,
    OperationEvidenceStore,
    StoredOperationEvidence,
    persist_operation_step_evidence,
    reconstruct_check_jump_hosts_semantic_facts,
    semantic_projection_digest,
    validate_operation_evidence_checkpoint,
    validate_operation_evidence_intents,
)
from scylla_vms.ansible.operation_execution import (
    OperationExecutionStore,
    OperationStepExecution,
)
from scylla_vms.ansible.service import (
    ConnectivityStatus,
    DestinationProbeStatus,
    HostConnectivityStatus,
    InventoryPreflightEvidence,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock, ClusterReadLock
from scylla_vms.persistence import serialize_json
from scylla_vms.process import ProcessResult

_OTHER_DIGEST = "sha256:" + "b" * 64


def _read(prepared: PreparedCoordinator) -> StoredOperationEvidence:
    with ClusterReadLock(prepared.paths, 0) as lock:
        return OperationEvidenceStore(prepared.paths, _OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
            expected_operation="check-jump-hosts",
        )


def _complete(
    tmp_path: Path, *, request_arguments: tuple[str, ...] = ()
) -> tuple[PreparedCoordinator, StoredOperationEvidence]:
    prepared = _prepare(tmp_path, request_arguments=request_arguments)
    _orchestrate(prepared, FakeCoordinatorRunner(_successful_results(prepared)))
    return prepared, _read(prepared)


def _step(
    prepared: PreparedCoordinator,
    sequence: int,
) -> OperationStepExecution:
    with ClusterReadLock(prepared.paths, 0) as lock:
        execution = OperationExecutionStore(prepared.paths, _OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
            expected_operation="check-jump-hosts",
        )
    attempt = execution.record.attempts[sequence - 1]
    intent = _intents_for_request(prepared.request, prepared.inventory)[sequence - 1]
    return OperationStepExecution(
        operation_id=_OPERATION_ID,
        operation="check-jump-hosts",
        step_sequence=sequence,
        playbook=attempt.playbook,
        classification=attempt.classification,
        limit=attempt.limit,
        variables=intent.variables,
        tags=intent.tags,
        check=intent.check,
        diff=intent.diff,
        verbosity=intent.verbosity,
        variables_digest=attempt.variables_digest,
        command_digest=attempt.command_digest,
        playbook_source_digest=attempt.playbook_source_digest,
        result_schema_version=attempt.result_schema_version,
    )


def _inventory_evidence(
    projection: InventoryPreflightProjection,
) -> InventoryPreflightEvidence:
    return InventoryPreflightEvidence(
        projection.status.value,
        projection.host_count,
        projection.target_count,
        projection.inventory_generation,
        projection.inventory_digest,
        projection.observation_generation,
        projection.observation_digest,
    )


def test_exact_two_step_projection_is_address_free_and_reconstructable(
    tmp_path: Path,
) -> None:
    prepared, stored = _complete(tmp_path)

    assert stored.record.schema_version == ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION
    assert stored.record.generation == 2
    assert tuple(item.step_sequence for item in stored.record.entries) == (1, 2)
    assert tuple(item.playbook for item in stored.record.entries) == (
        "inventory-preflight",
        "connectivity-check",
    )
    assert stored.record.entries[0].projection_schema_version == (
        INVENTORY_PREFLIGHT_PROJECTION_SCHEMA_VERSION
    )
    assert stored.record.entries[1].projection_schema_version == (
        CONNECTIVITY_PROJECTION_SCHEMA_VERSION
    )
    intents = _intents_for_request(prepared.request, prepared.inventory)
    facts = reconstruct_check_jump_hosts_semantic_facts(
        stored,
        binding=prepared.binding,
        context=prepared.operation_context,
        intents=intents,
    )
    assert facts.inventory_preflight.status is InventoryPreflightStatus.PASSED
    assert facts.connectivity.status is ConnectivityStatus.SUCCESS
    assert tuple(item.logical_id for item in facts.connectivity.hosts) == (
        "jump-host-1",
    )
    encoded = OperationEvidenceStore(prepared.paths, _OPERATION_ID).path.read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "10.0.0.",
        "203.0.113.",
        "PRIVATE KEY",
        "PLAY RECAP",
        "DSV_TCP",
        "stdout",
        "stderr",
    ):
        assert forbidden not in encoded


def test_destination_pair_projection_retains_only_requested_semantics(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        request_arguments=(
            "--destination",
            "scylla",
            "--depth",
            "route",
            "--destination-check",
            "scylla=9042",
        ),
    )
    _coordinate(prepared, FakeCoordinatorRunner(_results(prepared)))
    _coordinate(
        prepared,
        FakeCoordinatorRunner(
            _results(
                prepared,
                ProcessResult(
                    0,
                    _tcp_recap("scylla-ad-1-1", "scylla", 9042),
                    "",
                ),
            )
        ),
    )

    stored = _read(prepared)
    connectivity = stored.record.entries[1].projection
    assert isinstance(connectivity, ConnectivityProjection)
    assert tuple(item.to_object() for item in connectivity.destination_pairs) == (
        {
            "jump_host_id": "jump-host-1",
            "port": 9042,
            "protocol": "tcp",
            "role": "scylla",
            "status": "passed",
            "target_logical_id": "scylla-ad-1-1",
        },
    )
    encoded = json.dumps(connectivity.to_object())
    assert "10.0.0." not in encoded
    with pytest.raises(StatePersistenceError):
        DestinationPairProjection(
            "jump-host-1",
            "scylla-ad-1-1",
            "scylla",
            22,
            "tcp",
            DestinationProbeStatus.PASSED,
        )


def test_unknown_duplicate_and_unrequested_host_or_pair_are_refused(
    tmp_path: Path,
) -> None:
    prepared, stored = _complete(tmp_path)
    entry = stored.record.entries[1]
    projection = entry.projection
    assert isinstance(projection, ConnectivityProjection)

    with pytest.raises(StatePersistenceError, match="duplicated"):
        ConnectivityProjection(
            ConnectivityStatus.SUCCESS,
            (projection.hosts[0], projection.hosts[0]),
            (),
        )
    unknown = ConnectivityProjection(
        ConnectivityStatus.SUCCESS,
        (ConnectivityHostProjection("jump-host-2", HostConnectivityStatus.REACHABLE),),
        (),
    )
    unknown_entry = replace(
        entry,
        projection=unknown,
        projection_digest=semantic_projection_digest(unknown),
    )
    unknown_stored = StoredOperationEvidence(
        replace(
            stored.record,
            entries=(stored.record.entries[0], unknown_entry),
        ),
        stored.digest,
    )
    with pytest.raises(StateConflictError, match="target membership"):
        validate_operation_evidence_intents(
            unknown_stored,
            _intents_for_request(prepared.request, prepared.inventory),
        )

    pair = DestinationPairProjection(
        "jump-host-1",
        "scylla-ad-1-1",
        "scylla",
        9042,
        "tcp",
        DestinationProbeStatus.PASSED,
    )
    with pytest.raises(StatePersistenceError, match="duplicated"):
        ConnectivityProjection(
            ConnectivityStatus.SUCCESS,
            projection.hosts,
            (pair, pair),
        )
    unrequested = ConnectivityProjection(
        ConnectivityStatus.SUCCESS,
        projection.hosts,
        (pair,),
    )
    unrequested_entry = replace(
        entry,
        projection=unrequested,
        projection_digest=semantic_projection_digest(unrequested),
    )
    with pytest.raises(StateConflictError, match="target membership"):
        validate_operation_evidence_intents(
            StoredOperationEvidence(
                replace(
                    stored.record,
                    entries=(stored.record.entries[0], unrequested_entry),
                ),
                stored.digest,
            ),
            _intents_for_request(prepared.request, prepared.inventory),
        )


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",
        "2001:db8::1",
        "/private/operator/id_ed25519",
        "obviously-fake-secret",
        "operator-token",
        "SHA256:abcdefghijklmnop",
        "ssh-ed25519",
        "stdout",
    ],
)
def test_address_path_raw_output_and_secret_like_ids_are_refused(value: str) -> None:
    with pytest.raises(StatePersistenceError, match="invalid or protected"):
        ConnectivityHostProjection(value, HostConnectivityStatus.REACHABLE)


@pytest.mark.parametrize("mutation", ["extra", "status", "projection-extra"])
def test_malformed_and_extra_persisted_fields_fail_closed(
    tmp_path: Path, mutation: str
) -> None:
    prepared, _ = _complete(tmp_path)
    store = OperationEvidenceStore(prepared.paths, _OPERATION_ID)
    document = json.loads(store.path.read_text(encoding="utf-8"))
    if mutation == "extra":
        document["stdout"] = "forbidden"
    elif mutation == "status":
        document["entries"][1]["projection"]["status"] = "healthy"
    else:
        document["entries"][1]["projection"]["raw_output"] = "forbidden"
    store.path.write_bytes(serialize_json(document))
    store.path.chmod(0o600)

    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(StatePersistenceError),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
        )


@pytest.mark.parametrize(
    "drift",
    ["source", "readiness", "inventory", "trust", "context"],
)
def test_provenance_drift_is_refused(tmp_path: Path, drift: str) -> None:
    prepared, stored = _complete(tmp_path)
    binding = prepared.binding
    context = prepared.operation_context
    readiness = prepared.readiness
    if drift == "context":
        context = replace(context, digest=_OTHER_DIGEST)
    elif drift == "readiness":
        readiness = replace(readiness, inventory_digest=_OTHER_DIGEST)
    else:
        field = {
            "source": "source_digest",
            "inventory": "inventory_digest",
            "trust": "trust_digest",
        }[drift]
        binding = replace(
            binding,
            record=replace(binding.record, **{field: _OTHER_DIGEST}),
        )
    with pytest.raises(StateConflictError, match="drifted"):
        validate_operation_evidence_checkpoint(
            stored,
            binding=binding,
            context=context,
            readiness=readiness,
        )


def test_append_is_idempotent_only_for_the_exact_latest_entry(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    _coordinate(prepared, FakeCoordinatorRunner(_results(prepared)))
    stored = _read(prepared)
    first = stored.record.entries[0].projection
    assert isinstance(first, InventoryPreflightProjection)
    before = OperationEvidenceStore(prepared.paths, _OPERATION_ID).path.read_bytes()
    step = _step(prepared, 1)
    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        repeated, repeated_entry = persist_operation_step_evidence(
            lock,
            prepared.paths,
            prepared.binding,
            prepared.operation_context,
            prepared.readiness,
            step,
            _inventory_evidence(first),
        )
    assert repeated == stored
    assert repeated_entry == stored.record.entries[0]
    assert (
        OperationEvidenceStore(prepared.paths, _OPERATION_ID).path.read_bytes()
        == before
    )

    conflict = replace(_inventory_evidence(first), status="failed")
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="conflicts"),
    ):
        persist_operation_step_evidence(
            lock,
            prepared.paths,
            prepared.binding,
            prepared.operation_context,
            prepared.readiness,
            step,
            conflict,
        )

    complete, complete_stored = _complete(tmp_path / "complete")
    complete_first = complete_stored.record.entries[0].projection
    assert isinstance(complete_first, InventoryPreflightProjection)
    complete_step = _step(complete, 1)
    with (
        ClusterLock(complete.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="not the latest"),
    ):
        persist_operation_step_evidence(
            lock,
            complete.paths,
            complete.binding,
            complete.operation_context,
            complete.readiness,
            complete_step,
            _inventory_evidence(complete_first),
        )
    with pytest.raises(StatePersistenceError, match="entries or generation"):
        replace(
            complete_stored.record,
            entries=tuple(reversed(complete_stored.record.entries)),
        )


def test_evidence_store_lock_permissions_and_symlink_safety(tmp_path: Path) -> None:
    prepared, _ = _complete(tmp_path / "permissions")
    store = OperationEvidenceStore(prepared.paths, _OPERATION_ID)
    assert store.path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(UnsafePathError, match="not canonical"):
        OperationEvidenceStore(
            replace(prepared.paths, operations=prepared.paths.logs),
            _OPERATION_ID,
        )
    first = _read(prepared).record.entries[0].projection
    assert isinstance(first, InventoryPreflightProjection)
    first_step = _step(prepared, 1)
    with (
        ClusterLock(prepared.paths, "show", 0) as lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        persist_operation_step_evidence(
            lock,
            prepared.paths,
            prepared.binding,
            prepared.operation_context,
            prepared.readiness,
            first_step,
            _inventory_evidence(first),
        )
    store.path.chmod(0o644)
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(UnsafePathError, match="0600"),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
        )

    symlinked = _prepare(tmp_path / "symlink")
    symlink_store = OperationEvidenceStore(symlinked.paths, _OPERATION_ID)
    target = symlinked.paths.operations / "outside.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    symlink_store.path.symlink_to(target)
    with (
        ClusterReadLock(symlinked.paths, 0) as lock,
        pytest.raises(UnsafePathError, match="symbolic link"),
    ):
        symlink_store.read_locked(
            lock,
            expected_cluster_uuid=symlinked.metadata.record.cluster_uuid,
            expected_cluster_name=symlinked.metadata.record.cluster_name,
        )

    unlocked = ClusterLock(symlinked.paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError):
        symlink_store.read_locked(
            unlocked,
            expected_cluster_uuid=symlinked.metadata.record.cluster_uuid,
            expected_cluster_name=symlinked.metadata.record.cluster_name,
        )
