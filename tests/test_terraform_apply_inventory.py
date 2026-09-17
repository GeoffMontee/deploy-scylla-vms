import inspect
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
import test_ssh_trust_readiness as trust_helpers
from test_provider_source import CLUSTER_UUID
from test_terraform_apply_verification import (
    OutputRunner,
    _prepare_success,
    _valid_output,
    _verify,
)
from test_terraform_operation_composition import _rewrite_json
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.trust import TrustRecord
from scylla_vms.errors import (
    StateConflictError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import (
    InventoryRecord,
    InventoryRefreshService,
    InventoryStore,
    StoredInventoryRecord,
    _inventory_digest,
)
from scylla_vms.journal import JournalStatus, OperationJournalStore, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateRecord, ObservedStateStore
from scylla_vms.persistence import ClusterMetadataStore, serialize_json
from scylla_vms.terraform.apply_inventory import (
    TERRAFORM_APPLY_INVENTORY_REPORT_SCHEMA_VERSION,
    TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION,
    TerraformApplyInventoryCompanionState,
    TerraformApplyInventoryNextStep,
    TerraformApplyInventoryState,
    TerraformApplyInventoryStore,
    TerraformApplyInventoryTrustStatus,
    generate_deploy_inventory,
    terraform_apply_inventory_path,
)
from scylla_vms.terraform.apply_verification import (
    terraform_apply_verification_path,
)
from scylla_vms.terraform.outputs import parse_terraform_output_bundle


def _generate(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return generate_deploy_inventory(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
        )


def _verified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    runner = OutputRunner(json.dumps(_valid_output(prepared)))
    _verify(prepared, executable, runner)
    assert len(runner.calls) == 1
    return prepared


def _persist_inventory(prepared, *, when: datetime) -> StoredInventoryRecord:
    metadata = ClusterMetadataStore(prepared.paths).read(
        expected_cluster_name="example",
        expected_provider="oci",
    )
    observation = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    service = InventoryRefreshService(prepared.paths)
    refresh = service.prepare(
        metadata.record,
        observation,
        None,
        clock=lambda: when,
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return service.write(refresh, None, approved=True, lock=lock)


def _persist_trust(
    prepared,
    observation,
    inventory: StoredInventoryRecord,
    *,
    inventory_override: InventoryRecord | None = None,
) -> TrustRecord:
    bound_inventory = inventory_override or inventory.record
    entries = tuple(
        trust_helpers._trusted(host, index)
        for index, host in enumerate(
            bound_inventory.inventory.hosts,
            start=1,
        )
    )
    record = TrustRecord.create(
        observation.record,
        bound_inventory,
        entries,
        generation=1,
    )
    prepared.paths.ansible_trust.write_bytes(serialize_json(record.to_object()))
    prepared.paths.ansible_trust.chmod(0o600)
    return record


def _preexisting_observation_and_inventory(prepared) -> StoredInventoryRecord:
    bundle = parse_terraform_output_bundle(
        json.dumps(_valid_output(prepared)),
        expected_cluster_uuid=CLUSTER_UUID,
    )
    observation = ObservedStateRecord.create(
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        provider="oci",
        manifest=bundle.manifest,
        clock=lambda: datetime(2026, 9, 18, 20, 0, tzinfo=UTC),
    )
    metadata = ClusterMetadataStore(prepared.paths).read(
        expected_cluster_name="example",
        expected_provider="oci",
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored_observation = ObservedStateStore(prepared.paths).write_locked(
            observation,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        service = InventoryRefreshService(prepared.paths)
        refresh = service.prepare(
            metadata.record,
            stored_observation,
            None,
            clock=lambda: datetime(2026, 9, 18, 20, 0, 1, tzinfo=UTC),
        )
        return service.write(refresh, None, approved=True, lock=lock)


def test_inventory_api_accepts_only_canonical_identity_and_lock() -> None:
    assert tuple(inspect.signature(generate_deploy_inventory).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )


def test_verified_apply_creates_redacted_inventory_without_advancing_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    before_runtime = (
        prepared.paths.known_hosts.exists(),
        prepared.paths.ansible_ssh_config.exists(),
        prepared.paths.ansible_config.exists(),
    )

    report = _generate(prepared)

    assert report.schema_version == TERRAFORM_APPLY_INVENTORY_REPORT_SCHEMA_VERSION
    assert report.companion_schema_version == TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
    assert report.companion_state is TerraformApplyInventoryCompanionState.CREATED
    assert report.inventory_state is TerraformApplyInventoryState.CREATED
    assert report.inventory_generation == 1
    assert report.trust_status is TerraformApplyInventoryTrustStatus.MISSING
    assert report.next_step is (
        TerraformApplyInventoryNextStep.TRUST_ESTABLISHMENT_REQUIRED
    )
    assert report.machine_validation_state == "not-performed"
    assert report.readiness_state == "not-performed"
    assert report.ansible_state == "not-started"
    assert report.finalization_state == "not-started"
    assert not report.automatic_retry_allowed
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert prepared.paths.ansible_inventory.stat().st_mode & 0o777 == 0o600
    assert before_runtime == (
        prepared.paths.known_hosts.exists(),
        prepared.paths.ansible_ssh_config.exists(),
        prepared.paths.ansible_config.exists(),
    )
    journal = OperationJournalStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert journal.record.status is JournalStatus.IN_PROGRESS
    assert journal.record.phase is OperationPhase.VERIFY
    companion_text = terraform_apply_inventory_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    projection = json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        "10.0.0.",
        "ocid1.instance",
        str(prepared.paths.state_root),
        "ansible_host",
        "public_key",
        "fingerprint",
    ):
        assert protected not in companion_text
        assert protected not in projection


def test_exact_inventory_and_companion_are_reused_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    first = _generate(prepared)
    inventory_before = prepared.paths.ansible_inventory.read_bytes()
    companion_before = terraform_apply_inventory_path(
        prepared.paths, OPERATION_ID
    ).read_bytes()

    second = _generate(prepared)

    assert first.inventory_artifact_digest == second.inventory_artifact_digest
    assert second.inventory_state is TerraformApplyInventoryState.REUSED
    assert second.companion_state is TerraformApplyInventoryCompanionState.REUSED
    assert prepared.paths.ansible_inventory.read_bytes() == inventory_before
    assert (
        terraform_apply_inventory_path(prepared.paths, OPERATION_ID).read_bytes()
        == companion_before
    )


def test_completed_inventory_allows_zero_process_verifier_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    _verify(
        prepared,
        executable,
        OutputRunner(json.dumps(_valid_output(prepared))),
    )
    _generate(prepared)
    replay = OutputRunner("not-json")

    report = _verify(prepared, executable, replay)

    assert replay.calls == []
    assert report.journal_phase is OperationPhase.VERIFY


def test_new_verified_observation_advances_only_inventory_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    prior_inventory = _preexisting_observation_and_inventory(prepared)
    _verify(
        prepared,
        executable,
        OutputRunner(json.dumps(_valid_output(prepared))),
    )

    report = _generate(prepared)

    assert prior_inventory.record.generation == 1
    assert report.inventory_state is TerraformApplyInventoryState.UPDATED
    assert report.inventory_generation == 2
    stored = InventoryStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    assert stored.record.source_manifest_generation == 2
    assert stored.record.inventory == prior_inventory.record.inventory


@pytest.mark.parametrize(
    "artifact",
    ["verification", "journal", "metadata", "source", "tfvars", "observation"],
)
def test_missing_or_stale_verified_binding_refuses_before_inventory_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    if artifact == "verification":
        terraform_apply_verification_path(prepared.paths, OPERATION_ID).unlink()
    elif artifact == "journal":
        _rewrite_json(
            prepared.paths.operations / f"{OPERATION_ID}.json",
            lambda value: value.__setitem__("generation", 99),
        )
    else:
        path = {
            "metadata": prepared.paths.cluster_metadata,
            "source": prepared.paths.terraform_source_record,
            "tfvars": prepared.paths.terraform_tfvars,
            "observation": prepared.paths.terraform_observed,
        }[artifact]
        _rewrite_json(path, lambda _value: None, canonical=False)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _generate(prepared)

    assert not prepared.paths.ansible_inventory.exists()
    assert not terraform_apply_inventory_path(prepared.paths, OPERATION_ID).exists()


def test_post_verification_state_drift_refuses_before_inventory_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    state = json.loads(prepared.paths.terraform_state.read_text(encoding="utf-8"))
    state["resources"] = [{"mode": "managed", "type": "null_resource"}]
    prepared.paths.terraform_state.write_text(
        json.dumps(state, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    prepared.paths.terraform_state.chmod(0o600)

    with pytest.raises(StateConflictError, match="stale or conflicting"):
        _generate(prepared)

    assert not prepared.paths.ansible_inventory.exists()


def test_existing_trust_is_reported_current_without_rendering_runtime_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    inventory = _persist_inventory(
        prepared, when=datetime(2026, 9, 19, 1, 0, tzinfo=UTC)
    )
    observation = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    _persist_trust(prepared, observation, inventory)

    report = _generate(prepared)

    assert report.inventory_state is TerraformApplyInventoryState.REUSED
    assert report.trust_status is TerraformApplyInventoryTrustStatus.CURRENT
    assert report.next_step is (
        TerraformApplyInventoryNextStep.MACHINE_VALIDATION_REQUIRED
    )
    assert not prepared.paths.known_hosts.exists()
    assert not prepared.paths.ansible_ssh_config.exists()
    assert not prepared.paths.ansible_config.exists()


def test_generation_update_marks_semantically_matching_trust_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    prior_inventory = _preexisting_observation_and_inventory(prepared)
    prior_observation = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    _persist_trust(prepared, prior_observation, prior_inventory)
    _verify(
        prepared,
        executable,
        OutputRunner(json.dumps(_valid_output(prepared))),
    )

    report = _generate(prepared)

    assert report.inventory_state is TerraformApplyInventoryState.UPDATED
    assert report.trust_status is TerraformApplyInventoryTrustStatus.STALE
    assert report.next_step is (
        TerraformApplyInventoryNextStep.TRUST_REVALIDATION_REQUIRED
    )


def test_trust_endpoint_conflict_refuses_without_rewriting_inventory_or_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    inventory = _persist_inventory(
        prepared, when=datetime(2026, 9, 19, 1, 0, tzinfo=UTC)
    )
    observation = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    first_host = inventory.record.inventory.hosts[0]
    changed_host = replace(
        first_host,
        private_address="10.200.0.10",
        ansible_host=(
            first_host.public_address
            if first_host.public_address is not None
            else "10.200.0.10"
        ),
    )
    changed_hosts = (changed_host, *inventory.record.inventory.hosts[1:])
    changed_model = replace(inventory.record.inventory, hosts=changed_hosts)
    changed_inventory = replace(
        inventory.record,
        inventory_digest=_inventory_digest(changed_model),
        inventory=changed_model,
    )
    _persist_trust(
        prepared,
        observation,
        inventory,
        inventory_override=changed_inventory,
    )
    inventory_before = prepared.paths.ansible_inventory.read_bytes()
    trust_before = prepared.paths.ansible_trust.read_bytes()

    with pytest.raises(StateConflictError, match=r"trust.*conflicts"):
        _generate(prepared)

    assert prepared.paths.ansible_inventory.read_bytes() == inventory_before
    assert prepared.paths.ansible_trust.read_bytes() == trust_before
    assert not terraform_apply_inventory_path(prepared.paths, OPERATION_ID).exists()


def test_inventory_only_partial_state_recovers_after_companion_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    original = TerraformApplyInventoryStore.write_locked

    def fail_write(*args, **kwargs):
        raise StatePersistenceError(
            "fake inventory companion failure SHOULD-NOT-PERSIST"
        )

    monkeypatch.setattr(TerraformApplyInventoryStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError, match="fake inventory companion"):
        _generate(prepared)
    assert prepared.paths.ansible_inventory.exists()
    assert not terraform_apply_inventory_path(prepared.paths, OPERATION_ID).exists()
    inventory_before = prepared.paths.ansible_inventory.read_bytes()

    monkeypatch.setattr(TerraformApplyInventoryStore, "write_locked", original)
    report = _generate(prepared)

    assert report.inventory_state is TerraformApplyInventoryState.REUSED
    assert report.companion_state is TerraformApplyInventoryCompanionState.CREATED
    assert report.recovered_inventory
    assert prepared.paths.ansible_inventory.read_bytes() == inventory_before


def test_companion_only_orphan_fails_without_inventory_recreation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    _generate(prepared)
    companion = terraform_apply_inventory_path(prepared.paths, OPERATION_ID)
    companion_before = companion.read_bytes()
    prepared.paths.ansible_inventory.unlink()

    with pytest.raises(StateConflictError, match="without inventory"):
        _generate(prepared)

    assert not prepared.paths.ansible_inventory.exists()
    assert companion.read_bytes() == companion_before


def test_mismatched_companion_fails_without_inventory_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    _generate(prepared)
    inventory_before = prepared.paths.ansible_inventory.read_bytes()
    companion = terraform_apply_inventory_path(prepared.paths, OPERATION_ID)
    _rewrite_json(
        companion,
        lambda value: value.__setitem__("inventory_digest", "sha256:" + "f" * 64),
    )

    with pytest.raises(StatePersistenceError, match="record digest conflicts"):
        _generate(prepared)

    assert prepared.paths.ansible_inventory.read_bytes() == inventory_before


def test_unsafe_inventory_and_companion_paths_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    target = tmp_path / "inventory-target"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    prepared.paths.ansible_inventory.symlink_to(target)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        _generate(prepared)
    prepared.paths.ansible_inventory.unlink()

    companion = terraform_apply_inventory_path(prepared.paths, OPERATION_ID)
    companion.write_text("{}", encoding="utf-8")
    companion.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        _generate(prepared)


def test_ambiguous_operation_artifact_refuses_without_inventory_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    ambiguous = prepared.paths.terraform_plans / f"{OPERATION_ID}.unknown.json"
    ambiguous.write_text("{}", encoding="utf-8")
    ambiguous.chmod(0o600)

    with pytest.raises(StateConflictError, match="ambiguous"):
        _generate(prepared)

    assert not prepared.paths.ansible_inventory.exists()


def test_inventory_conflict_does_not_silently_rewrite_runtime_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _verified(tmp_path, monkeypatch)
    inventory = _persist_inventory(
        prepared, when=datetime(2026, 9, 19, 1, 0, tzinfo=UTC)
    )
    value = inventory.record.to_object()
    hostvars = value["all"]["hosts"]
    logical_id = sorted(hostvars)[0]
    hostvars[logical_id]["ansible_user"] = "operator"
    prepared.paths.ansible_inventory.write_bytes(serialize_json(value))
    prepared.paths.ansible_inventory.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _generate(prepared)

    assert not terraform_apply_inventory_path(prepared.paths, OPERATION_ID).exists()
