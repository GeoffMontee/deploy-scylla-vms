import inspect
import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
import test_ssh_trust_readiness as trust_helpers
import test_terraform_apply_inventory as inventory_helpers
from test_provider_source import CLUSTER_UUID
from test_terraform_apply_verification import (
    OutputRunner,
    _prepare_success,
    _valid_output,
    _verify,
)
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.trust as trust_module
from scylla_vms.ansible.routed_keyscan import (
    ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION,
    RoutedCandidateStatus,
    RoutedCandidateTarget,
    RoutedHostKeyCandidateCollection,
    routed_keyscan_route_digest,
)
from scylla_vms.ansible.trust import (
    HostEndpoint,
    HostKeyCandidate,
    TrustCaptureSource,
    TrustConfirmation,
    TrustRecord,
    TrustStore,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import InventoryHost, InventoryStore, StoredInventoryRecord
from scylla_vms.journal import JournalStatus, OperationJournalStore, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.persistence import (
    digest_bytes,
    format_timestamp,
    parse_timestamp,
)
from scylla_vms.terraform.apply_trust import (
    TERRAFORM_APPLY_TRUST_REPORT_SCHEMA_VERSION,
    TERRAFORM_APPLY_TRUST_SCHEMA_VERSION,
    TerraformApplyTrustCompanionState,
    TerraformApplyTrustDerivativeState,
    TerraformApplyTrustNextStep,
    TerraformApplyTrustProof,
    TerraformApplyTrustProofStatus,
    TerraformApplyTrustStage,
    TerraformApplyTrustState,
    TerraformApplyTrustStore,
    establish_deploy_ssh_trust,
    terraform_apply_trust_path,
)


def _prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[object, StoredObservedState, StoredInventoryRecord]:
    prepared = inventory_helpers._verified(tmp_path, monkeypatch)
    inventory_helpers._generate(prepared)
    observation = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    inventory = InventoryStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    return prepared, observation, inventory


def _candidate(
    host: InventoryHost,
    observation: StoredObservedState,
    seed: int,
    *,
    routed: bool = False,
) -> HostKeyCandidate:
    base = trust_helpers._candidate(host, seed)
    return replace(
        base,
        captured_at=(
            observation.record.captured_at
            if not routed
            else format_timestamp(
                parse_timestamp(observation.record.captured_at) + timedelta(seconds=1)
            )
        ),
        capture_source=(
            TrustCaptureSource.ROUTED_JUMP_KEYSCAN
            if routed
            else TrustCaptureSource.SUPPLIED_CANDIDATE
        ),
    )


def _proof(
    candidate: HostKeyCandidate,
    confirmation: TrustConfirmation = TrustConfirmation.EXPLICIT_OPERATOR,
) -> TerraformApplyTrustProof:
    return TerraformApplyTrustProof(
        candidate.logical_id,
        candidate.algorithm,
        confirmation,
        (
            candidate.fingerprint
            if confirmation is TrustConfirmation.EXPECTED_FINGERPRINT
            else None
        ),
    )


def _call(
    prepared,
    *,
    direct: tuple[HostKeyCandidate, ...] = (),
    routed: tuple[RoutedHostKeyCandidateCollection, ...] = (),
    proofs: tuple[TerraformApplyTrustProof, ...] = (),
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return establish_deploy_ssh_trust(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            direct,
            routed,
            proofs,
        )


def _jump_stage(
    prepared,
    observation: StoredObservedState,
    inventory: StoredInventoryRecord,
    *,
    confirmation: TrustConfirmation = TrustConfirmation.EXPLICIT_OPERATOR,
):
    jump = next(
        host for host in inventory.record.inventory.hosts if host.jump_host_id is None
    )
    candidate = _candidate(jump, observation, 1)
    report = _call(
        prepared,
        direct=(candidate,),
        proofs=(_proof(candidate, confirmation),),
    )
    return report, candidate


def _routed_collection(
    prepared,
    observation: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> tuple[
    RoutedHostKeyCandidateCollection,
    tuple[TerraformApplyTrustProof, ...],
]:
    trust = TrustStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
    targets: list[RoutedCandidateTarget] = []
    proofs: list[TerraformApplyTrustProof] = []
    for seed, host in enumerate(
        (
            host
            for host in inventory.record.inventory.hosts
            if host.jump_host_id is not None
        ),
        start=2,
    ):
        assert host.jump_host_id is not None
        jump = hosts[host.jump_host_id]
        candidate = _candidate(host, observation, seed, routed=True)
        targets.append(
            RoutedCandidateTarget(
                host.logical_id,
                host.provider_id,
                host.jump_host_id,
                routed_keyscan_route_digest(jump, host),
                RoutedCandidateStatus.COLLECTED,
                (candidate,),
                (),
            )
        )
        proofs.append(_proof(candidate))
    collection = RoutedHostKeyCandidateCollection(
        format_timestamp(
            parse_timestamp(observation.record.captured_at) + timedelta(seconds=1)
        ),
        "collected",
        observation.record.generation,
        observation.record.manifest_digest,
        inventory.record.generation,
        inventory.digest,
        trust.record.generation,
        trust.digest,
        "deploy-scylla-vms.ansible-readiness/v1",
        digest_bytes(b"already-obtained machine readiness"),
        10,
        tuple(sorted({cast(str, target.jump_host_id) for target in targets})),
        tuple(sorted(targets, key=lambda item: item.logical_id)),
        ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION,
    )
    return collection, tuple(proofs)


def _complete(prepared, observation, inventory):
    _jump_stage(prepared, observation, inventory)
    collection, proofs = _routed_collection(prepared, observation, inventory)
    report = _call(prepared, routed=(collection,), proofs=proofs)
    return report, collection, proofs


def test_trust_api_accepts_only_canonical_identity_candidates_and_proofs() -> None:
    assert tuple(inspect.signature(establish_deploy_ssh_trust).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "direct_candidates",
        "routed_candidate_collections",
        "proofs",
    )
    assert "yes" not in inspect.signature(establish_deploy_ssh_trust).parameters


def test_explicit_jump_then_routed_private_trust_completes_redacted_companion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)

    staged, _ = _jump_stage(prepared, observation, inventory)

    assert staged.stage is TerraformApplyTrustStage.JUMP_TRUST_CURRENT
    assert staged.next_step is TerraformApplyTrustNextStep.PRIVATE_TRUST_PENDING
    assert staged.trust_state is TerraformApplyTrustState.CREATED
    assert staged.derivative_state is TerraformApplyTrustDerivativeState.CREATED
    assert staged.companion_state is TerraformApplyTrustCompanionState.NOT_CREATED
    assert staged.trusted_host_count == 1
    assert not terraform_apply_trust_path(prepared.paths, OPERATION_ID).exists()

    complete, collection, _ = _complete_from_stage(prepared, observation, inventory)

    assert complete.schema_version == TERRAFORM_APPLY_TRUST_REPORT_SCHEMA_VERSION
    assert complete.stage is TerraformApplyTrustStage.COMPLETE
    assert complete.next_step is (
        TerraformApplyTrustNextStep.MACHINE_VALIDATION_REQUIRED
    )
    assert complete.trust_state is TerraformApplyTrustState.ADVANCED
    assert complete.companion_state is TerraformApplyTrustCompanionState.CREATED
    assert complete.proof_status is TerraformApplyTrustProofStatus.ACCEPTED
    assert complete.trusted_host_count == complete.host_count == 4
    assert complete.machine_validation_state == "not-performed"
    assert complete.readiness_state == "not-performed"
    assert complete.ansible_state == "not-started"
    assert complete.finalization_state == "not-started"
    assert not complete.automatic_retry_allowed
    assert prepared.paths.known_hosts.stat().st_mode & 0o777 == 0o600
    assert prepared.paths.ansible_ssh_config.stat().st_mode & 0o777 == 0o600
    assert "ProxyCommand" not in prepared.paths.ansible_ssh_config.read_text(
        encoding="utf-8"
    )
    companion_text = terraform_apply_trust_path(prepared.paths, OPERATION_ID).read_text(
        encoding="utf-8"
    )
    report_text = json.dumps(complete.to_object(), sort_keys=True)
    for protected in (
        "10.0.0.",
        "ocid1.instance",
        "ssh-ed25519",
        collection.targets[0].candidates[0].fingerprint,
        collection.targets[0].candidates[0].public_key,
        str(prepared.paths.state_root),
    ):
        assert protected not in companion_text
        assert protected not in report_text
    journal = OperationJournalStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert journal.record.status is JournalStatus.IN_PROGRESS
    assert journal.record.phase is OperationPhase.VERIFY


def _complete_from_stage(prepared, observation, inventory):
    collection, proofs = _routed_collection(prepared, observation, inventory)
    return _call(prepared, routed=(collection,), proofs=proofs), collection, proofs


def test_first_jump_trust_accepts_independent_matching_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)

    report, candidate = _jump_stage(
        prepared,
        observation,
        inventory,
        confirmation=TrustConfirmation.EXPECTED_FINGERPRINT,
    )

    stored = TrustStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    assert report.stage is TerraformApplyTrustStage.JUMP_TRUST_CURRENT
    assert stored.record.entries[0].confirmation is (
        TrustConfirmation.EXPECTED_FINGERPRINT
    )
    assert stored.record.entries[0].fingerprint == candidate.fingerprint


def test_simultaneous_untrusted_jump_and_private_candidates_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    jump = next(
        host for host in inventory.record.inventory.hosts if host.jump_host_id is None
    )
    private = next(
        host
        for host in inventory.record.inventory.hosts
        if host.jump_host_id is not None
    )
    jump_candidate = _candidate(jump, observation, 1)
    private_candidate = _candidate(private, observation, 2, routed=True)
    fake_collection = RoutedHostKeyCandidateCollection(
        observation.record.captured_at,
        "collected",
        observation.record.generation,
        observation.record.manifest_digest,
        inventory.record.generation,
        inventory.digest,
        1,
        digest_bytes(b"untrusted jump"),
        "deploy-scylla-vms.ansible-readiness/v1",
        digest_bytes(b"fake readiness"),
        10,
        (cast(str, private.jump_host_id),),
        (),
    )

    with pytest.raises(StateConflictError, match="simultaneously"):
        _call(
            prepared,
            direct=(jump_candidate,),
            routed=(fake_collection,),
            proofs=(_proof(jump_candidate), _proof(private_candidate)),
        )

    assert not prepared.paths.ansible_trust.exists()


def test_routed_candidate_route_and_policy_conflicts_fail_before_and_after_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    _jump_stage(prepared, observation, inventory)
    collection, proofs = _routed_collection(prepared, observation, inventory)
    first, *remaining = collection.targets
    wrong_route = replace(
        collection,
        targets=(
            replace(first, route_digest=digest_bytes(b"wrong route")),
            *remaining,
        ),
    )

    with pytest.raises(StateConflictError, match=r"route|target"):
        _call(prepared, routed=(wrong_route,), proofs=proofs)
    with pytest.raises(StateConflictError, match="policy"):
        _call(
            prepared,
            routed=(
                replace(
                    collection,
                    readiness_schema_version=("deploy-scylla-vms.ansible-readiness/v2"),
                ),
            ),
            proofs=proofs,
        )

    completed = _call(prepared, routed=(collection,), proofs=proofs)
    assert completed.stage is TerraformApplyTrustStage.COMPLETE
    with pytest.raises(StateConflictError, match=r"route|target"):
        _call(prepared, routed=(wrong_route,), proofs=proofs)


def test_exact_complete_trust_and_companion_reentry_is_write_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    first, _, _ = _complete(prepared, observation, inventory)
    before = (
        prepared.paths.ansible_trust.read_bytes(),
        prepared.paths.known_hosts.read_bytes(),
        prepared.paths.ansible_ssh_config.read_bytes(),
        terraform_apply_trust_path(prepared.paths, OPERATION_ID).read_bytes(),
    )

    second = _call(prepared)

    assert second.trust_state is TerraformApplyTrustState.REUSED
    assert second.derivative_state is TerraformApplyTrustDerivativeState.CURRENT
    assert second.companion_state is TerraformApplyTrustCompanionState.REUSED
    assert second.proof_status is TerraformApplyTrustProofStatus.REUSED
    assert first.companion_artifact_digest == second.companion_artifact_digest
    assert before == (
        prepared.paths.ansible_trust.read_bytes(),
        prepared.paths.known_hosts.read_bytes(),
        prepared.paths.ansible_ssh_config.read_bytes(),
        terraform_apply_trust_path(prepared.paths, OPERATION_ID).read_bytes(),
    )


def test_stale_matching_trust_requires_explicit_revalidation_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    prior_inventory = inventory_helpers._preexisting_observation_and_inventory(prepared)
    prior_observation = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    entries = tuple(
        trust_helpers._trusted(host, seed)
        for seed, host in enumerate(prior_inventory.record.inventory.hosts, start=1)
    )
    stale = TrustRecord.create(
        prior_observation.record,
        prior_inventory.record,
        entries,
        generation=1,
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        TrustStore(prepared.paths).write_locked(
            stale,
            prior_observation,
            prior_inventory,
            approved=True,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    _verify(
        prepared,
        executable,
        OutputRunner(json.dumps(_valid_output(prepared))),
    )
    inventory_helpers._generate(prepared)

    with pytest.raises(StateConflictError, match="one explicit proof"):
        _call(prepared)

    proofs = tuple(
        TerraformApplyTrustProof(
            entry.logical_id,
            entry.algorithm,
            entry.confirmation,
            (
                entry.fingerprint
                if entry.confirmation is TrustConfirmation.EXPECTED_FINGERPRINT
                else None
            ),
        )
        for entry in entries
    )
    report = _call(prepared, proofs=proofs)

    assert report.trust_state is TerraformApplyTrustState.REVALIDATED
    assert report.stage is TerraformApplyTrustStage.COMPLETE
    assert report.trust_generation == 2


@pytest.mark.parametrize(
    "case",
    ["missing", "extra", "duplicate", "provider", "endpoint", "route"],
)
def test_direct_candidate_set_and_identity_conflicts_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    jump = next(
        host for host in inventory.record.inventory.hosts if host.jump_host_id is None
    )
    private = next(
        host
        for host in inventory.record.inventory.hosts
        if host.jump_host_id is not None
    )
    candidate = _candidate(jump, observation, 1)
    candidates = (candidate,)
    proofs = (_proof(candidate),)
    if case == "missing":
        candidates = ()
    elif case == "extra":
        extra = _candidate(private, observation, 2)
        candidates = (candidate, extra)
    elif case == "duplicate":
        candidates = (candidate, candidate)
    elif case == "provider":
        candidates = (replace(candidate, provider_id="ocid1.instance.oc1.iad.changed"),)
    elif case == "endpoint":
        candidates = (replace(candidate, endpoint=HostEndpoint("10.99.0.1")),)
    elif case == "route":
        candidates = (replace(candidate, jump_host_id="jump-host-other"),)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, direct=candidates, proofs=proofs)

    assert not prepared.paths.ansible_trust.exists()


def test_unsupported_malformed_and_generic_yes_proofs_are_refused() -> None:
    host = trust_helpers._host(
        "jump-host-1",
        trust_helpers.HostRole.JUMP_HOST,
        "10.0.0.10",
    )
    candidate = trust_helpers._candidate(host, 1)
    with pytest.raises(StatePersistenceError, match="disallowed"):
        replace(candidate, algorithm="ssh-rsa")
    with pytest.raises(StatePersistenceError, match="malformed"):
        replace(candidate, public_key="not-base64")
    with pytest.raises(StatePersistenceError, match="proof is invalid"):
        TerraformApplyTrustProof(
            candidate.logical_id,
            candidate.algorithm,
            cast(TrustConfirmation, "yes"),
        )
    with pytest.raises(StatePersistenceError, match="fingerprint"):
        TerraformApplyTrustProof(
            candidate.logical_id,
            candidate.algorithm,
            TrustConfirmation.EXPECTED_FINGERPRINT,
            "SHA256:not-valid",
        )


@pytest.mark.parametrize("failure_name", ["known_hosts", "ssh_config"])
def test_runtime_write_failure_leaves_exact_recoverable_trust_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_name: str,
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    jump = next(
        host for host in inventory.record.inventory.hosts if host.jump_host_id is None
    )
    candidate = _candidate(jump, observation, 1)
    original = trust_module._atomic_text

    def fail_selected(path: Path, text: str) -> None:
        if path.name == failure_name:
            raise StatePersistenceError("fake SSH derivative write failure")
        original(path, text)

    monkeypatch.setattr(trust_module, "_atomic_text", fail_selected)
    with pytest.raises(StatePersistenceError, match="fake SSH derivative"):
        _call(
            prepared,
            direct=(candidate,),
            proofs=(_proof(candidate),),
        )
    assert prepared.paths.ansible_trust.exists()
    monkeypatch.setattr(trust_module, "_atomic_text", original)

    report = _call(
        prepared,
        direct=(candidate,),
        proofs=(_proof(candidate),),
    )

    assert report.stage is TerraformApplyTrustStage.JUMP_TRUST_CURRENT
    assert report.derivative_state is TerraformApplyTrustDerivativeState.RECOVERED
    assert report.recovered_partial_state


def test_trust_and_companion_write_failures_recover_without_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    jump = next(
        host for host in inventory.record.inventory.hosts if host.jump_host_id is None
    )
    candidate = _candidate(jump, observation, 1)
    original_trust_write = TrustStore.write_locked

    def fail_trust(*args, **kwargs):
        raise StatePersistenceError("fake trust metadata failure")

    monkeypatch.setattr(TrustStore, "write_locked", fail_trust)
    with pytest.raises(StatePersistenceError, match="fake trust metadata"):
        _call(prepared, direct=(candidate,), proofs=(_proof(candidate),))
    assert not prepared.paths.ansible_trust.exists()
    assert not prepared.paths.known_hosts.exists()
    monkeypatch.setattr(TrustStore, "write_locked", original_trust_write)
    _call(prepared, direct=(candidate,), proofs=(_proof(candidate),))

    collection, proofs = _routed_collection(prepared, observation, inventory)
    original_companion_write = TerraformApplyTrustStore.write_locked

    def fail_companion(*args, **kwargs):
        raise StatePersistenceError("fake trust companion failure")

    monkeypatch.setattr(TerraformApplyTrustStore, "write_locked", fail_companion)
    with pytest.raises(StatePersistenceError, match="fake trust companion"):
        _call(prepared, routed=(collection,), proofs=proofs)
    assert not terraform_apply_trust_path(prepared.paths, OPERATION_ID).exists()
    assert (
        len(
            TrustStore(prepared.paths)
            .read(
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
                expected_provider="oci",
            )
            .record.entries
        )
        == 4
    )
    monkeypatch.setattr(
        TerraformApplyTrustStore, "write_locked", original_companion_write
    )

    recovered = _call(prepared, routed=(collection,), proofs=proofs)

    assert recovered.trust_state is TerraformApplyTrustState.REUSED
    assert recovered.companion_state is TerraformApplyTrustCompanionState.CREATED


def test_staged_trust_advance_failure_recovers_removed_derivatives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    _jump_stage(prepared, observation, inventory)
    collection, proofs = _routed_collection(prepared, observation, inventory)
    original_write = TrustStore.write_locked

    def fail_advance(*args, **kwargs):
        raise StatePersistenceError("fake staged trust metadata failure")

    monkeypatch.setattr(TrustStore, "write_locked", fail_advance)
    with pytest.raises(StatePersistenceError, match="fake staged trust"):
        _call(prepared, routed=(collection,), proofs=proofs)
    assert prepared.paths.ansible_trust.exists()
    assert not prepared.paths.known_hosts.exists()
    assert not prepared.paths.ansible_ssh_config.exists()
    monkeypatch.setattr(TrustStore, "write_locked", original_write)

    recovered = _call(prepared, routed=(collection,), proofs=proofs)

    assert recovered.stage is TerraformApplyTrustStage.COMPLETE
    assert recovered.trust_state is TerraformApplyTrustState.ADVANCED
    assert recovered.recovered_partial_state


def test_companion_or_derivative_conflict_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    _complete(prepared, observation, inventory)
    trust_before = prepared.paths.ansible_trust.read_bytes()
    prepared.paths.known_hosts.write_text("conflicting\n", encoding="utf-8")
    prepared.paths.known_hosts.chmod(0o600)

    with pytest.raises(StateConflictError, match="known_hosts conflicts"):
        _call(prepared)

    assert prepared.paths.ansible_trust.read_bytes() == trust_before
    prepared.paths.known_hosts.unlink()
    prepared.paths.ansible_trust.unlink()
    with pytest.raises(StateConflictError, match="without trust"):
        _call(prepared)


def test_lock_symlink_permission_and_ambiguous_path_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    jump = next(
        host for host in inventory.record.inventory.hosts if host.jump_host_id is None
    )
    candidate = _candidate(jump, observation, 1)
    with (
        ClusterLock(prepared.paths, "show", 0) as lock,
        pytest.raises(StateLockError),
    ):
        establish_deploy_ssh_trust(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            (candidate,),
            (),
            (_proof(candidate),),
        )

    target = tmp_path / "trust-target"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    prepared.paths.ansible_trust.symlink_to(target)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        _call(prepared, direct=(candidate,), proofs=(_proof(candidate),))
    prepared.paths.ansible_trust.unlink()

    companion = terraform_apply_trust_path(prepared.paths, OPERATION_ID)
    companion.write_text("{}", encoding="utf-8")
    companion.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        _call(prepared, direct=(candidate,), proofs=(_proof(candidate),))
    companion.unlink()

    ambiguous = prepared.paths.terraform_plans / f"{OPERATION_ID}.trust-extra.json"
    ambiguous.write_text("{}", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared, direct=(candidate,), proofs=(_proof(candidate),))


def test_companion_schema_round_trip_is_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, observation, inventory = _prepared(tmp_path, monkeypatch)
    report, _, _ = _complete(prepared, observation, inventory)
    stored = TerraformApplyTrustStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )

    assert stored.record.schema_version == TERRAFORM_APPLY_TRUST_SCHEMA_VERSION
    assert stored.record.from_object(stored.record.to_object()) == stored.record
    assert report.companion_record_digest == stored.record.record_digest
