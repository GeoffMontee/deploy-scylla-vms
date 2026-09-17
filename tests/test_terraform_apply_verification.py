import copy
import inspect
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import test_provider_source
from test_provider_source import CLUSTER_UUID
from test_terraform_apply_execution import (
    FakeRunner as ApplyRunner,
)
from test_terraform_apply_execution import (
    _executable,
    _execute,
    _ready,
)
from test_terraform_operation_composition import _rewrite_json
from test_terraform_outputs import _host, _output, _storage
from test_terraform_plan_checkpoint import (
    ADDRESS_MARKER,
    OPERATION_ID,
    SECRET_MARKER,
    STATE_LINEAGE,
    _toolchain,
)

import scylla_vms.terraform.state_safeguard as state_safeguard
from scylla_vms.errors import (
    StateConflictError,
    StatePersistenceError,
    TerraformError,
    ToolExecutionError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationJournalStore, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateRecord, ObservedStateStore
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)
from scylla_vms.terraform.apply_verification import (
    TERRAFORM_APPLY_VERIFICATION_REPORT_SCHEMA_VERSION,
    TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION,
    TerraformApplyVerificationCompanionState,
    TerraformApplyVerificationStatus,
    TerraformApplyVerificationStore,
    TerraformObservationWriteState,
    TerraformStateProgression,
    terraform_apply_verification_path,
    verify_deploy_apply,
)
from scylla_vms.terraform.inputs import TerraformInputStore
from scylla_vms.terraform.outputs import parse_terraform_output_bundle
from scylla_vms.terraform.toolchain import TerraformToolchain, TerraformVersion


class OutputRunner:
    def __init__(
        self,
        stdout: str,
        *,
        exit_code: int = 0,
        failure: str | None = None,
        inspect: Callable[[], None] | None = None,
    ) -> None:
        self.stdout = stdout
        self.exit_code = exit_code
        self.failure = failure
        self.inspect = inspect
        self.calls: list[ProcessSpec] = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        if self.inspect is not None:
            self.inspect()
        if self.failure == "timeout":
            raise ProcessTimeoutError("fake timeout SHOULD-NOT-PERSIST")
        if self.failure in {"non-utf8", "oversized"}:
            raise ProcessOutputError("fake invalid output SHOULD-NOT-PERSIST")
        if self.failure == "error":
            raise ToolExecutionError("fake output error SHOULD-NOT-PERSIST")
        return ProcessResult(
            self.exit_code,
            self.stdout,
            "fake provider diagnostic SHOULD-NOT-PERSIST",
        )


def _prepare_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    initial_state: bool = True,
):
    capabilities = test_provider_source._capabilities
    monkeypatch.setattr(
        test_provider_source,
        "_capabilities",
        lambda: capabilities(local_count=1, local_gib=1000),
    )
    prepared = _ready(tmp_path, write_state=initial_state)
    executable = _executable(tmp_path)
    _execute(prepared, executable, ApplyRunner())
    state = {
        "lineage": (
            STATE_LINEAGE if initial_state else "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        ),
        "resources": [{"instances": [{"attributes": {"value": "fake"}}]}],
        "serial": 8 if initial_state else 1,
        "terraform_version": "1.6.6",
        "version": 4,
    }
    prepared.paths.terraform_state.write_text(
        json.dumps(state, sort_keys=True), encoding="utf-8"
    )
    prepared.paths.terraform_state.chmod(0o600)
    return prepared, executable


def _valid_output(prepared) -> dict[str, object]:
    terraform_input = (
        TerraformInputStore(prepared.paths)
        .read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )
        .record.terraform_input
    )
    value = _output()
    cluster_uuid = str(terraform_input.cluster_uuid)
    value["host_manifest"]["value"]["cluster_uuid"] = cluster_uuid
    hosts: list[dict[str, object]] = []
    for index, input_host in enumerate(terraform_input.hosts, start=1):
        input_storage = input_host.storage
        if input_storage.selected_backend.value == "boot-only":
            storage = _storage("boot-only", input_host.logical_id)
        elif input_storage.selected_backend.value == "block-volume":
            assert input_storage.block_volume is not None
            storage = _storage(
                "block-volume",
                input_host.logical_id,
                requested=input_storage.requested_backend.value,
                count=input_storage.block_volume.count,
            )
            for device in storage["devices"]:
                device["size_gib"] = input_storage.block_volume.size_gib
            storage["raw_total_gib"] = (
                input_storage.block_volume.count * input_storage.block_volume.size_gib
            )
            storage["usable_total_gib"] = storage["raw_total_gib"]
        else:
            assert input_storage.provider_local_device_count is not None
            assert input_storage.provider_local_total_gib is not None
            storage = _storage(
                "local-nvme",
                input_host.logical_id,
                requested=input_storage.requested_backend.value,
                count=input_storage.provider_local_device_count,
            )
            storage["devices"][0]["size_gib"] = input_storage.provider_local_total_gib
            storage["raw_total_gib"] = input_storage.provider_local_total_gib
            storage["usable_total_gib"] = input_storage.provider_local_total_gib
        storage["layout"] = input_storage.layout
        storage["policy_digest"] = input_storage.policy_digest
        storage["selection_algorithm"] = input_storage.selection_algorithm
        storage["selection_status"] = (
            "final"
            if input_storage.selected_backend.value == "boot-only"
            else "provisional"
        )
        storage["storage_generation"] = 1
        host = _host(
            input_host.logical_id,
            input_host.role.value,
            input_host.zone,
            f"10.0.0.{index + 10}",
            storage,
            jump_host_id=(
                None if input_host.role.value == "jump-host" else "jump-host-1"
            ),
        )
        host["public_address"] = None
        host["scylla_datacenter"] = input_host.scylla_datacenter
        host["scylla_rack"] = input_host.scylla_rack
        hosts.append(host)
    value["host_manifest"]["value"]["hosts"] = hosts

    images = value["image_selection"]["value"]
    images["cluster_uuid"] = cluster_uuid
    images["images"] = [
        {
            "filter": {
                "operating_system": "Ubuntu",
                "operating_system_version": "24.04",
                "version_match": "exact",
            },
            "image_id": host.image_id,
            "image_name": host.image_name,
            "image_time_created": host.image_time_created,
            "logical_id": host.logical_id,
            "role": host.role.value,
            "shape": host.shape,
        }
        for host in terraform_input.hosts
    ]

    network = value["network_evidence"]["value"]
    network["cluster_uuid"] = cluster_uuid
    network["mode"] = "existing"
    network["vcn_id"] = terraform_input.network.vcn_id
    network["ownership"] = {
        "gateways": False,
        "route_tables": False,
        "subnets": False,
        "vcn": False,
    }
    subnet_ids = dict(terraform_input.network.subnet_ids)
    network["subnets"] = [
        {
            "access": "private",
            "owned": False,
            "role": host.role.value,
            "subnet_id": subnet_ids[host.role.value],
            "zone": host.zone,
        }
        for host in terraform_input.hosts
    ]
    network["subnets"].sort(key=lambda item: (item["zone"], item["role"]))
    return value


def _verify(prepared, executable: Path, runner: OutputRunner):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return verify_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            runner,
            executable,
            _toolchain(),
        )


def test_verification_api_accepts_only_canonical_dependencies() -> None:
    assert tuple(inspect.signature(verify_deploy_apply).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "terraform_executable",
        "toolchain",
    )


@pytest.mark.parametrize(
    ("initial_state", "progression"),
    [
        (False, TerraformStateProgression.INITIALIZED),
        (True, TerraformStateProgression.ADVANCED),
    ],
)
def test_success_reconciles_output_without_finalizing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_state: bool,
    progression: TerraformStateProgression,
) -> None:
    prepared, executable = _prepare_success(
        tmp_path, monkeypatch, initial_state=initial_state
    )
    runner = OutputRunner(json.dumps(_valid_output(prepared)))

    report = _verify(prepared, executable, runner)

    assert report.schema_version == TERRAFORM_APPLY_VERIFICATION_REPORT_SCHEMA_VERSION
    assert report.verification_schema_version == (
        TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
    )
    assert report.verification_status is (
        TerraformApplyVerificationStatus.INFRASTRUCTURE_OBSERVATION_RECONCILED
    )
    assert report.state_progression is progression
    assert report.observation_write_state is TerraformObservationWriteState.INITIAL
    assert report.companion_state is TerraformApplyVerificationCompanionState.CREATED
    assert report.runner_invoked is True
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.inventory_state == "pending"
    assert report.trust_state == "pending"
    assert report.ansible_state == "not-started"
    assert report.finalization_state == "not-started"
    journal = OperationJournalStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert journal.record.evidence[-1].phase is OperationPhase.VERIFY
    assert journal.record.evidence[-1].summary_code == (
        "terraform-output-baseline-absent"
    )
    assert len(runner.calls) == 1
    call = runner.calls[0]
    assert call.argv == (
        str(executable),
        f"-chdir={prepared.paths.terraform_work}",
        "output",
        "-json",
        "-no-color",
        f"-state={prepared.paths.terraform_state}",
    )
    assert call.cwd == prepared.paths.cluster_root
    environment = call.environment.for_subprocess()
    assert {
        name: value
        for name, value in environment.items()
        if name != "__CF_USER_TEXT_ENCODING"
    } == {
        "CHECKPOINT_DISABLE": "1",
        "HOME": str(prepared.paths.terraform),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TF_DATA_DIR": str(prepared.paths.terraform_data),
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
        "TF_PLUGIN_CACHE_DIR": str(prepared.paths.terraform_plugin_cache),
    }
    assert set(environment) <= {
        "CHECKPOINT_DISABLE",
        "HOME",
        "LANG",
        "LC_ALL",
        "TF_DATA_DIR",
        "TF_IN_AUTOMATION",
        "TF_INPUT",
        "TF_PLUGIN_CACHE_DIR",
        "__CF_USER_TEXT_ENCODING",
    }
    persisted = terraform_apply_verification_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    projection = json.dumps(report.to_object(), sort_keys=True)
    for protected in (SECRET_MARKER, ADDRESS_MARKER, "10.0.0.11", "ocid1.instance"):
        assert protected not in persisted
        assert protected not in projection


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda state: state.update(
                {"lineage": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}
            ),
            "lineage",
        ),
        (lambda state: state.update({"serial": 7}), "advance"),
    ],
)
def test_state_progression_conflicts_refuse_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, object]], None],
    message: str,
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    state = json.loads(prepared.paths.terraform_state.read_text(encoding="utf-8"))
    mutate(state)
    prepared.paths.terraform_state.write_text(
        json.dumps(state, sort_keys=True), encoding="utf-8"
    )
    prepared.paths.terraform_state.chmod(0o600)
    runner = OutputRunner(json.dumps(_valid_output(prepared)))

    with pytest.raises(StateConflictError, match=message):
        _verify(prepared, executable, runner)

    assert runner.calls == []


@pytest.mark.parametrize("failure", ["timeout", "non-utf8", "oversized", "error"])
def test_output_runner_failures_never_publish_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    runner = OutputRunner(json.dumps(_valid_output(prepared)), failure=failure)

    with pytest.raises((ProcessTimeoutError, ProcessOutputError, ToolExecutionError)):
        _verify(prepared, executable, runner)

    assert len(runner.calls) == 1
    assert not prepared.paths.terraform_observed.exists()
    assert not terraform_apply_verification_path(prepared.paths, OPERATION_ID).exists()
    replay = OutputRunner(json.dumps(_valid_output(prepared)))
    with pytest.raises(StateConflictError, match="manual recovery"):
        _verify(prepared, executable, replay)
    assert replay.calls == []


def test_nonzero_output_exit_is_not_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    runner = OutputRunner(
        json.dumps(_valid_output(prepared)),
        exit_code=1,
    )

    with pytest.raises(ToolExecutionError, match="exact successful"):
        _verify(prepared, executable, runner)

    assert len(runner.calls) == 1
    assert not prepared.paths.terraform_observed.exists()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value["host_manifest"].update({"sensitive": True}),
        lambda value: value["host_manifest"]["value"]["hosts"].pop(),
        lambda value: value["host_manifest"]["value"]["hosts"][1].update(
            {"logical_id": "jump-host-1"}
        ),
        lambda value: value["image_selection"]["value"]["images"][0].update(
            {"image_id": "ocid1.image.oc1.iad.wrong"}
        ),
        lambda value: value["network_evidence"]["value"]["subnets"][0].update(
            {"subnet_id": "ocid1.subnet.oc1.iad.wrong"}
        ),
    ],
)
def test_malformed_or_mismatched_output_is_never_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    value = copy.deepcopy(_valid_output(prepared))
    mutate(value)
    runner = OutputRunner(json.dumps(value))

    with pytest.raises((StateConflictError, TerraformError, ToolExecutionError)):
        _verify(prepared, executable, runner)

    assert len(runner.calls) == 1
    assert not prepared.paths.terraform_observed.exists()


def test_duplicate_output_keys_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    payload = json.dumps(_valid_output(prepared)).replace(
        '"sensitive": false',
        '"sensitive": false, "sensitive": false',
        1,
    )
    runner = OutputRunner(payload)

    with pytest.raises(TerraformError, match="duplicate"):
        _verify(prepared, executable, runner)

    assert len(runner.calls) == 1
    assert not prepared.paths.terraform_observed.exists()


def test_idempotent_reentry_makes_no_output_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    first = OutputRunner(json.dumps(_valid_output(prepared)))
    _verify(prepared, executable, first)
    second = OutputRunner("not-json")

    report = _verify(prepared, executable, second)

    assert report.companion_state is TerraformApplyVerificationCompanionState.REUSED
    assert report.runner_invoked is False
    assert second.calls == []
    apply_replay = ApplyRunner()
    execution_report = _execute(prepared, executable, apply_replay)
    assert execution_report.runner_invoked is False
    assert apply_replay.calls == []


def test_existing_observation_advances_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    bundle = parse_terraform_output_bundle(
        json.dumps(_valid_output(prepared)), expected_cluster_uuid=CLUSTER_UUID
    )
    candidate = ObservedStateRecord.create(
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        provider="oci",
        manifest=bundle.manifest,
        clock=lambda: datetime(2026, 9, 18, 20, 0, tzinfo=UTC),
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        ObservedStateStore(prepared.paths).write_locked(
            candidate,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    runner = OutputRunner(json.dumps(_valid_output(prepared)))

    report = _verify(prepared, executable, runner)

    assert report.observation_generation == 2
    assert report.observation_write_state is TerraformObservationWriteState.UPDATED
    assert report.runner_invoked is True


def test_prior_observation_identity_drift_blocks_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    prior_output = copy.deepcopy(_valid_output(prepared))
    prior_output["host_manifest"]["value"]["hosts"][0]["provider_id"] = (
        "ocid1.instance.oc1.iad.priorfake"
    )
    prior_bundle = parse_terraform_output_bundle(
        json.dumps(prior_output), expected_cluster_uuid=CLUSTER_UUID
    )
    candidate = ObservedStateRecord.create(
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        provider="oci",
        manifest=prior_bundle.manifest,
        clock=lambda: datetime(2026, 9, 18, 20, 0, tzinfo=UTC),
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored = ObservedStateStore(prepared.paths).write_locked(
            candidate,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    runner = OutputRunner(json.dumps(_valid_output(prepared)))

    with pytest.raises(StateConflictError, match="exactly match"):
        _verify(prepared, executable, runner)

    assert len(runner.calls) == 1
    current = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    assert current == stored
    assert not terraform_apply_verification_path(prepared.paths, OPERATION_ID).exists()


def test_observation_only_recovery_does_not_rerun_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    original = TerraformApplyVerificationStore.write_locked

    def fail_record_write(*args, **kwargs):
        raise StatePersistenceError(
            "fake verification write failure SHOULD-NOT-PERSIST"
        )

    monkeypatch.setattr(
        TerraformApplyVerificationStore, "write_locked", fail_record_write
    )
    first = OutputRunner(json.dumps(_valid_output(prepared)))
    with pytest.raises(StatePersistenceError, match="fake verification"):
        _verify(prepared, executable, first)
    assert len(first.calls) == 1
    assert prepared.paths.terraform_observed.exists()
    assert not terraform_apply_verification_path(prepared.paths, OPERATION_ID).exists()

    monkeypatch.setattr(TerraformApplyVerificationStore, "write_locked", original)
    second = OutputRunner("not-json")
    report = _verify(prepared, executable, second)
    assert report.companion_state is (
        TerraformApplyVerificationCompanionState.RECOVERED_OBSERVATION
    )
    assert report.runner_invoked is False
    assert report.recovered_observation is True
    assert second.calls == []


def test_missing_successful_execution_refuses_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capabilities = test_provider_source._capabilities
    monkeypatch.setattr(
        test_provider_source,
        "_capabilities",
        lambda: capabilities(local_count=1, local_gib=1000),
    )
    prepared = _ready(tmp_path)
    executable = _executable(tmp_path)
    runner = OutputRunner("{}")

    with pytest.raises(StateConflictError, match="execution record"):
        _verify(prepared, executable, runner)
    assert runner.calls == []


def test_uncertain_execution_never_enters_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capabilities = test_provider_source._capabilities
    monkeypatch.setattr(
        test_provider_source,
        "_capabilities",
        lambda: capabilities(local_count=1, local_gib=1000),
    )
    prepared = _ready(tmp_path)
    executable = _executable(tmp_path)
    _execute(prepared, executable, ApplyRunner(exit_code=1))
    runner = OutputRunner("{}")

    with pytest.raises(StateConflictError, match="eligible"):
        _verify(prepared, executable, runner)
    assert runner.calls == []


@pytest.mark.parametrize(
    "artifact",
    ["metadata", "source", "tfvars", "backend", "journal", "toolchain"],
)
def test_bound_input_drift_refuses_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    toolchain = _toolchain()
    if artifact == "metadata":
        _rewrite_json(
            prepared.paths.cluster_metadata, lambda value: None, canonical=False
        )
    elif artifact == "source":
        path = prepared.paths.terraform_work / "main.tf"
        path.write_bytes(path.read_bytes() + b"\n# fake drift\n")
        path.chmod(0o600)
    elif artifact == "tfvars":
        _rewrite_json(
            prepared.paths.terraform_tfvars, lambda value: None, canonical=False
        )
    elif artifact == "backend":
        path = prepared.paths.terraform_work / "terraform.tfstate"
        path.write_text("{}", encoding="utf-8")
        path.chmod(0o600)
    elif artifact == "journal":
        _rewrite_json(
            prepared.paths.operations / f"{OPERATION_ID}.json",
            lambda value: value.__setitem__("generation", 8),
        )
    else:
        toolchain = TerraformToolchain(TerraformVersion(1, 7, 0))
    runner = OutputRunner(json.dumps(_valid_output(prepared)))

    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)),
    ):
        verify_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            runner,
            executable,
            toolchain,
        )
    assert runner.calls == []


def test_unsafe_state_symlink_and_permissions_refuse_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    state_bytes = prepared.paths.terraform_state.read_bytes()
    prepared.paths.terraform_state.unlink()
    target = tmp_path / "other-state"
    target.write_bytes(state_bytes)
    target.chmod(0o600)
    prepared.paths.terraform_state.symlink_to(target)
    runner = OutputRunner(json.dumps(_valid_output(prepared)))

    with pytest.raises(UnsafePathError):
        _verify(prepared, executable, runner)
    assert runner.calls == []

    prepared.paths.terraform_state.unlink()
    prepared.paths.terraform_state.write_bytes(state_bytes)
    prepared.paths.terraform_state.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _verify(prepared, executable, runner)
    assert runner.calls == []


def test_state_hardlink_and_size_bound_refuse_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)
    runner = OutputRunner(json.dumps(_valid_output(prepared)))
    alias = tmp_path / "state-alias"
    os.link(prepared.paths.terraform_state, alias)
    with pytest.raises(UnsafePathError, match="hard links"):
        _verify(prepared, executable, runner)
    assert runner.calls == []

    alias.unlink()
    state = json.loads(prepared.paths.terraform_state.read_text(encoding="utf-8"))
    state["padding"] = "x" * 4096
    prepared.paths.terraform_state.write_text(
        json.dumps(state, sort_keys=True), encoding="utf-8"
    )
    prepared.paths.terraform_state.chmod(0o600)
    monkeypatch.setattr(state_safeguard, "_MAXIMUM_STATE_BYTES", 1024)
    with pytest.raises(StatePersistenceError, match="size"):
        _verify(prepared, executable, runner)
    assert runner.calls == []


def test_concurrent_state_replacement_during_output_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executable = _prepare_success(tmp_path, monkeypatch)

    def replace_state() -> None:
        replacement = prepared.paths.terraform_state.with_suffix(".replacement")
        replacement.write_bytes(prepared.paths.terraform_state.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, prepared.paths.terraform_state)

    runner = OutputRunner(json.dumps(_valid_output(prepared)), inspect=replace_state)
    with pytest.raises(
        (StateConflictError, UnsafePathError), match=r"changed|replaced"
    ):
        _verify(prepared, executable, runner)
    assert len(runner.calls) == 1
    assert not prepared.paths.terraform_observed.exists()
