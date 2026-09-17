import base64
import hashlib
import importlib.util
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_ansible_deploy_storage_preflight import (
    StoragePreflightRunner,
)
from test_ansible_deploy_storage_preflight import (
    _execute as _execute_preflight,
)
from test_ansible_deploy_storage_preflight import (
    _prepared as _preflight_prepared,
)
from test_ansible_deploy_storage_preflight import (
    _reconcile as _reconcile_preflight,
)
from test_ansible_deploy_storage_prepare_authorization import (
    _call as _authorize,
)
from test_ansible_deploy_storage_prepare_authorization import (
    _general,
    _wipe,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_storage_prepare_execution as execution_module
from scylla_vms.ansible.deploy_storage_preflight import (
    DeployStoragePreflightAction,
)
from scylla_vms.ansible.deploy_storage_prepare_execution import (
    ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION,
    DeployStoragePrepareEvidenceStore,
    DeployStoragePrepareExecution,
    DeployStoragePrepareExecutionState,
    DeployStoragePrepareExecutionStore,
    deploy_storage_prepare_evidence_path,
    deploy_storage_prepare_execution_path,
    execute_deploy_storage_prepare,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
from scylla_vms.ansible.storage_prepare import STORAGE_PREPARE_SCHEMA_VERSION
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_SECRET = "obviously-fake-storage-prepare-execution-secret"
_PRIVATE_PATH = "/private/operator/storage-prepare-execution.json"


def _storage_prepare_role_module() -> Any:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/storage_prepare/library"
        / "storage_prepare.py"
    )
    spec = importlib.util.spec_from_file_location("tested_storage_prepare_role", path)
    if spec is None or spec.loader is None:
        raise AssertionError("storage-prepare role module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass
class StoragePrepareRunner:
    mode: str = "success"
    inspect_started: Callable[[], None] | None = None
    specs: list[ProcessSpec] | None = None
    payloads: list[dict[str, object]] | None = None
    playbook_calls: int = 0

    def __post_init__(self) -> None:
        self.specs = []
        self.payloads = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        assert self.payloads is not None
        self.specs.append(spec)
        if spec.argv[-1] == "--version":
            name = Path(spec.argv[0]).name
            return ProcessResult(0, f"{name} [core 2.20.9]\n", "")
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if playbook != "storage-prepare":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        self.playbook_calls += 1
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object], variables["deploy_scylla_vms_storage_prepare"]
        )
        self.payloads.append(payload)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "interrupted":
            raise KeyboardInterrupt
        if self.mode == "non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (1024 * 1024), _SECRET)
        return self._result(payload)

    def _result(self, payload: dict[str, object]) -> ProcessResult:
        logical_id = cast(str, payload["logical_id"])
        authorization = cast(dict[str, object], payload["authorization"])
        disposition = cast(str, payload["classification"])
        wipe_required = disposition == StorageOwnershipStatus.WIPE_REVIEW_REQUIRED.value
        successful = self.mode not in {
            "failed",
            "failed-before-write",
            "failed-partial-wipe",
            "failed-revalidation",
            "unreachable",
        }
        prohibited = self.mode == "prohibited-action"
        if successful and not prohibited:
            completed_steps = (
                ["signatures-wiped", "xfs-formatted", "mounted", "marker-written"]
                if wipe_required
                else ["xfs-formatted", "mounted", "marker-written"]
            )
            status = "changed"
            irreversible = "completed"
            mutation_boundary = "completed"
            first_irreversible_step = completed_steps[0]
        elif prohibited:
            completed_steps = []
            status = "noop"
            irreversible = "not-started"
            mutation_boundary = "not-crossed"
            first_irreversible_step = None
        elif self.mode == "failed-revalidation":
            completed_steps = []
            status = "failed"
            irreversible = "not-started"
            mutation_boundary = "not-crossed"
            first_irreversible_step = None
        elif self.mode in {"failed-before-write", "failed-partial-wipe"}:
            completed_steps = []
            status = "failed"
            irreversible = "started"
            mutation_boundary = "crossed"
            first_irreversible_step = (
                "signatures-wiped" if wipe_required else "xfs-formatted"
            )
        else:
            completed_steps = (
                ["signatures-wiped"] if wipe_required else ["xfs-formatted"]
            )
            status = "failed"
            irreversible = "started"
            mutation_boundary = "crossed"
            first_irreversible_step = completed_steps[0]
        value: dict[str, object] = {
            "action": "prepare-required",
            "backend": payload["backend"],
            "completed": successful and not prohibited,
            "completed_steps": completed_steps,
            "device_set_digest": authorization["device_set_digest"],
            "disposition": disposition,
            "filesystem_uuid_digest": (
                "sha256:" + "f" * 64 if successful and not prohibited else None
            ),
            "first_irreversible_step": first_irreversible_step,
            "immediate_device_revalidation": (
                not prohibited and self.mode != "failed-revalidation"
            ),
            "irreversible_step_status": irreversible,
            "layout": payload["layout"],
            "logical_id": logical_id,
            "marker_digest": (
                "sha256:" + "a" * 64 if successful and not prohibited else None
            ),
            "mutation_boundary": mutation_boundary,
            "post_action_verification": (
                {"mount": True, "marker": True} if successful and not prohibited else {}
            ),
            "preparation_intent_digest": authorization["preparation_intent_digest"],
            "provenance_digest": payload["provenance_digest"],
            "schema_version": STORAGE_PREPARE_SCHEMA_VERSION,
            "status": status,
            "wipe_applied": (
                wipe_required
                and (bool(completed_steps) or self.mode == "failed-partial-wipe")
            ),
        }
        if self.mode == "malformed":
            value["unexpected"] = True
        elif self.mode == "wrong-device":
            value["device_set_digest"] = "sha256:" + "e" * 64
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        failed = self.mode in {
            "failed",
            "failed-before-write",
            "failed-partial-wipe",
            "failed-revalidation",
        }
        unreachable = self.mode == "unreachable"
        stdout = (
            f"ok: [{logical_id}] => "
            f'{{"msg":"DSV_STORAGE_PREPARE_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=8 changed={int(successful and not prohibited)} "
            f"unreachable={int(unreachable)} failed={int(failed)} "
            "skipped=0 rescued=0 ignored=0\n"
        )
        exit_code = 4 if unreachable else 2 if failed else 0
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
):
    prepared, _inventory, executables, toolchain = _preflight_prepared(
        tmp_path, monkeypatch, disposition
    )
    _execute_preflight(prepared, StoragePreflightRunner(), executables, toolchain)
    _reconcile_preflight(prepared)
    _authorize(
        prepared,
        _general(prepared),
        _wipe(prepared)
        if disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
        else None,
    )
    return prepared, executables, toolchain


def _call(prepared: Any, runner: Any, executables: Any, toolchain: Any):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def _records(prepared: Any):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployStoragePrepareExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployStoragePrepareEvidenceStore(prepared.paths, OPERATION_ID)
        evidence = (
            evidence_store.read_locked(
                lock,
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            if evidence_store.path.exists()
            else None
        )
    return execution, evidence


@pytest.mark.parametrize(
    ("disposition", "wipe_required"),
    (
        (StorageOwnershipStatus.CLEAN_NEW, False),
        (StorageOwnershipStatus.WIPE_REVIEW_REQUIRED, True),
    ),
)
def test_exact_scope_consumes_proofs_at_started_and_reentry_is_zero_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
    wipe_required: bool,
) -> None:
    assert tuple(inspect.signature(execute_deploy_storage_prepare).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch, disposition)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    show_before = _run_show(prepared.paths)

    def inspect_started() -> None:
        value = json.loads(
            deploy_storage_prepare_execution_path(
                prepared.paths, OPERATION_ID
            ).read_text(encoding="utf-8")
        )
        execution = DeployStoragePrepareExecution.from_object(value)
        attempt = execution.attempts[0]
        assert execution.state is DeployStoragePrepareExecutionState.STARTED
        assert attempt.general_authorization_consumed_at_start
        assert attempt.wipe_authorization_consumed_at_start is wipe_required
        assert not deploy_storage_prepare_evidence_path(
            prepared.paths, OPERATION_ID
        ).exists()

    runner = StoragePrepareRunner(inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert report.schema_version == (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployStoragePrepareExecutionState.SUCCEEDED
    assert report.invocation_count == report.scope_count == 1
    assert report.general_authorization_consumed
    assert report.wipe_authorization_consumed_count == int(wipe_required)
    assert report.wipe_applied_count == int(wipe_required)
    assert report.reconciliation_state == report.postcheck_state == "not-performed"
    assert not report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert not report.skip_allowed
    assert not report.continue_after_uncertainty_allowed
    assert not report.rollback_performed
    assert journal_path.read_bytes() == journal_bytes
    assert _run_show(prepared.paths) == show_before
    assert runner.playbook_calls == 1
    assert runner.payloads is not None
    payload = runner.payloads[0]
    assert payload["action"] == "prepare-required"
    assert payload["selection_mode"] == "public-device-identity-digest"
    assert payload["check_mode_requested"] is False
    role_module = _storage_prepare_role_module()
    assert role_module._validate_intent(payload) == payload
    assert (
        cast(dict[str, object], payload["authorization"])["wipe_acknowledged"]
        is wipe_required
    )

    second = StoragePrepareRunner()
    reused = _call(prepared, second, executables, toolchain)
    assert reused.execution_artifact_digest == report.execution_artifact_digest
    assert second.specs == []

    for path in (
        deploy_storage_prepare_execution_path(prepared.paths, OPERATION_ID),
        deploy_storage_prepare_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
        text = path.read_text(encoding="utf-8")
        for protected in (
            "/dev/",
            "ocid1.",
            "10.0.",
            "203.0.113.",
            "serial",
            "ansible-playbook",
            "--limit",
            _SECRET,
            _PRIVATE_PATH,
        ):
            assert protected not in text


def test_role_resolves_only_exact_public_identity_with_fake_device_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _storage_prepare_role_module()
    stable_id = "by-id:obviously-fake-storage-device"
    identity = "device-sha256:" + hashlib.sha256(stable_id.encode()).hexdigest()
    fake_path = "/dev/obviously-fake-storage-device"
    monkeypatch.setattr(
        module,
        "_lsblk",
        lambda: {
            fake_path: {
                "_parents": (),
                "fstype": None,
                "kname": "obviously-fake-storage-device",
                "mountpoints": [],
                "size": 4096,
                "type": "disk",
            }
        },
    )
    monkeypatch.setattr(
        module,
        "_by_id_links",
        lambda: {fake_path: [f"/dev/disk/by-id/{stable_id.removeprefix('by-id:')}"]},
    )
    monkeypatch.setattr(module, "_signatures", lambda _path: [])
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("real storage command was attempted")
        ),
    )
    monkeypatch.setattr(Path, "iterdir", lambda _self: iter(()))
    intent = {
        "classification": "clean-new",
        "devices": [{"capacity_bytes": 4096, "identity": identity}],
        "selection_mode": "public-device-identity-digest",
    }
    assert module._immediate_revalidate_deploy(intent) == [fake_path]
    assert intent["_resolved_stable_device_ids"] == [stable_id]


def test_role_reports_partial_wipe_at_irreversible_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _storage_prepare_role_module()
    paths = ["/dev/obviously-fake-storage-1", "/dev/obviously-fake-storage-2"]
    calls: list[tuple[str, ...]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> str:
        calls.append(tuple(argv))
        if argv[0] == module.COMMANDS["wipefs"] and len(calls) == 2:
            raise module.PreparationError("injected second-device wipe failure")
        return ""

    monkeypatch.setattr(module, "_immediate_revalidate", lambda _intent: paths)
    monkeypatch.setattr(module, "_run", fake_run)
    changed, result = module._prepare(
        {
            "action": "prepare-required",
            "authorization": {
                "device_set_digest": "sha256:" + "a" * 64,
                "preparation_intent_digest": "sha256:" + "b" * 64,
            },
            "backend": "local-nvme",
            "check_mode_requested": False,
            "classification": "wipe-review-required",
            "layout": "raid0",
            "logical_id": "scylla-ad-1-1",
            "provenance_digest": "sha256:" + "c" * 64,
            "selection_mode": "public-device-identity-digest",
        }
    )
    assert changed
    assert result["status"] == "failed"
    assert result["immediate_device_revalidation"] is True
    assert result["mutation_boundary"] == "crossed"
    assert result["first_irreversible_step"] == "signatures-wiped"
    assert result["wipe_applied"] is True
    assert "signatures-wiped" not in result["completed_steps"]
    assert len(calls) == 2

    class _FailedResult(Exception):
        pass

    failure: dict[str, object] = {}

    class _FakeAnsibleModule:
        def __init__(self, **_kwargs: object) -> None:
            self.params = {"intent": {}}
            self.check_mode = False

        def fail_json(self, **kwargs: object) -> None:
            failure.update(kwargs)
            raise _FailedResult

        def exit_json(self, **_kwargs: object) -> None:
            raise AssertionError("failed semantic evidence used a successful exit")

    monkeypatch.setattr(module, "AnsibleModule", _FakeAnsibleModule)
    monkeypatch.setattr(module, "_validate_intent", lambda _intent: {})
    monkeypatch.setattr(module, "_prepare", lambda _intent: (changed, result))
    with pytest.raises(_FailedResult):
        module.main()
    assert failure["changed"] is True
    assert failure["storage_prepare_result"] == result


def test_mixed_nonwipe_then_wipe_scope_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def digest(character: str) -> str:
        return "sha256:" + character * 64

    source = load_ansible_source_bundle()
    source_digest = execution_module._playbook_source_digest(source, "storage-prepare")
    definition = execution_module.get_playbook("storage-prepare")
    stable_ids = ("scylla-ad-1-1", "scylla-ad-1-2")
    dispositions = (
        StorageOwnershipStatus.CLEAN_NEW,
        StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
    )
    variables_digests = (digest("1"), digest("2"))
    command_digests = (digest("3"), digest("4"))
    authorized = tuple(
        SimpleNamespace(
            sequence=index,
            mapping_sequence=9,
            playbook="storage-prepare",
            classification=OperationClassification.DESTRUCTIVE,
            stable_id=stable_id,
            stable_id_digest=execution_module._digest_object(stable_id),
            action=DeployStoragePreflightAction.PREPARE_REQUIRED,
            disposition=disposition,
            device_count=1,
            device_set_digest=digest("a"),
            preparation_intent_digest=digest("b"),
            wipe_required=(disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED),
            target_digest=execution_module._digest_object([stable_id]),
            variables_digest=variables_digests[index - 1],
            source_digest=source_digest,
            command_digest=command_digests[index - 1],
        )
        for index, (stable_id, disposition) in enumerate(
            zip(stable_ids, dispositions, strict=True), start=1
        )
    )
    evidence_hosts = tuple(
        SimpleNamespace(
            stable_id=stable_id,
            action=DeployStoragePreflightAction.PREPARE_REQUIRED,
            blocker_set=(),
            disposition=disposition,
            device_count=1,
            device_set_digest=digest("a"),
            preparation_intent_digest=digest("b"),
            wipe_required=(disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED),
        )
        for stable_id, disposition in zip(stable_ids, dispositions, strict=True)
    )
    preflight_hosts = tuple(
        SimpleNamespace(
            logical_id=stable_id,
            ownership_status=disposition,
            blockers=(),
        )
        for stable_id, disposition in zip(stable_ids, dispositions, strict=True)
    )
    loaded = SimpleNamespace(
        source=source,
        planning=SimpleNamespace(
            base=SimpleNamespace(
                deploy=SimpleNamespace(
                    metadata=SimpleNamespace(record=object()),
                    observation=object(),
                    inventory=object(),
                )
            )
        ),
    )
    context = SimpleNamespace(
        evidence=SimpleNamespace(record=SimpleNamespace(hosts=evidence_hosts)),
        preflight=SimpleNamespace(
            preflight=SimpleNamespace(hosts=preflight_hosts),
            discovery=SimpleNamespace(
                post=SimpleNamespace(
                    chain=SimpleNamespace(
                        authorization_context=SimpleNamespace(
                            final_routes=SimpleNamespace(
                                post=SimpleNamespace(
                                    post=SimpleNamespace(
                                        base=SimpleNamespace(
                                            host=SimpleNamespace(loaded=loaded)
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
        ),
    )

    def fake_payload(
        _metadata: object,
        _observation: object,
        _inventory: object,
        _preflight: object,
        authorization: object,
        **_kwargs: object,
    ) -> dict[str, object]:
        return {
            "logical_id": authorization.logical_id,
            "provenance_digest": digest("c"),
        }

    class FakeBuilder:
        call_index = 0

        def validate_operation_step(
            self, _name: str, **kwargs: object
        ) -> tuple[object, object, str, str]:
            index = self.call_index
            self.call_index += 1
            return (
                definition,
                kwargs["variables"],
                variables_digests[index],
                command_digests[index],
            )

    monkeypatch.setattr(
        execution_module, "build_deploy_storage_prepare_payload", fake_payload
    )
    scopes = execution_module._derive_execution_scopes(
        context,
        SimpleNamespace(
            record=SimpleNamespace(
                operation_id=OPERATION_ID,
                preflight_evidence_digest=digest("e"),
                prepare_host_count=2,
                scopes=authorized,
            )
        ),
        builder=FakeBuilder(),
    )
    assert tuple(item.authorization.stable_id for item in scopes) == stable_ids
    assert tuple(item.authorization.wipe_required for item in scopes) == (
        False,
        True,
    )


@pytest.mark.parametrize(
    ("mode", "expected_state"),
    (
        ("timeout", DeployStoragePrepareExecutionState.TIMED_OUT),
        ("interrupted", DeployStoragePrepareExecutionState.INTERRUPTED),
        ("non-utf8", DeployStoragePrepareExecutionState.MALFORMED_RESULT),
        ("oversized", DeployStoragePrepareExecutionState.MALFORMED_RESULT),
        ("malformed", DeployStoragePrepareExecutionState.MALFORMED_RESULT),
        ("wrong-device", DeployStoragePrepareExecutionState.MALFORMED_RESULT),
        ("prohibited-action", DeployStoragePrepareExecutionState.MALFORMED_RESULT),
        ("failed", DeployStoragePrepareExecutionState.FAILED),
        ("failed-before-write", DeployStoragePrepareExecutionState.FAILED),
        ("failed-partial-wipe", DeployStoragePrepareExecutionState.FAILED),
        ("failed-revalidation", DeployStoragePrepareExecutionState.FAILED),
        ("unreachable", DeployStoragePrepareExecutionState.UNREACHABLE),
    ),
)
def test_uncertain_started_outcomes_are_manual_recovery_and_never_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_state: DeployStoragePrepareExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
    )
    runner = StoragePrepareRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery required"):
        _call(prepared, runner, executables, toolchain)
    execution, _evidence = _records(prepared)
    assert execution.record.state is expected_state
    assert execution.record.general_authorization_consumed
    assert execution.record.wipe_authorization_consumed_count == 1
    assert execution.record.attempts[0].manual_recovery_required
    assert not execution.record.attempts[0].automatic_retry_allowed
    call_count = runner.playbook_calls
    with pytest.raises(StateConflictError, match=r"manual recovery.*cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == call_count


def test_evidence_persistence_failure_leaves_started_no_retry_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )

    def fail_append(*_args: object, **_kwargs: object) -> object:
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(DeployStoragePrepareEvidenceStore, "append_locked", fail_append)
    runner = StoragePrepareRunner()
    with pytest.raises(
        StatePersistenceError, match=r"evidence persistence failed.*manual recovery"
    ):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployStoragePrepareExecutionState.STARTED
    assert evidence is None
    assert execution.record.attempts[0].manual_recovery_required
    assert runner.playbook_calls == 1
    with pytest.raises(StateConflictError, match=r"manual recovery.*cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1


def test_started_transition_cannot_rewrite_authorized_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    original = DeployStoragePrepareExecutionStore.write_locked

    def rewrite_started_scope(self, record, **kwargs):
        if record.state is DeployStoragePrepareExecutionState.STARTED:
            record = replace(
                record,
                attempts=(
                    *record.attempts[:-1],
                    replace(record.attempts[-1], stable_id="scylla-unauthorized"),
                ),
            )
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployStoragePrepareExecutionStore, "write_locked", rewrite_started_scope
    )
    runner = StoragePrepareRunner()
    with pytest.raises(
        StatePersistenceError,
        match="authorization consumption failed before invocation",
    ):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployStoragePrepareExecutionState.PREPARED
    assert execution.record.attempts[0].stable_id == "scylla-ad-1-1"
    assert evidence is None
    assert runner.playbook_calls == 0


def test_terminal_persistence_failure_leaves_evidence_bound_started_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    original = DeployStoragePrepareExecutionStore.write_locked

    def fail_terminal(self, record, **kwargs):
        if record.state is DeployStoragePrepareExecutionState.SUCCEEDED:
            raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployStoragePrepareExecutionStore, "write_locked", fail_terminal
    )
    runner = StoragePrepareRunner()
    with pytest.raises(
        StatePersistenceError, match=r"terminal persistence failed.*manual recovery"
    ):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployStoragePrepareExecutionState.STARTED
    assert evidence is not None
    assert len(evidence.record.entries) == 1
    assert runner.playbook_calls == 1
    with pytest.raises(StateConflictError):
        _call(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1


def test_post_invocation_drift_leaves_started_manual_recovery_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"

    def drift_after_start() -> None:
        value = json.loads(journal_path.read_text(encoding="utf-8"))
        value["request_digest"] = "sha256:" + "e" * 64
        journal_path.write_bytes(serialize_json(value))

    runner = StoragePrepareRunner(inspect_started=drift_after_start)
    with pytest.raises(StateConflictError, match="manual recovery required"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployStoragePrepareExecutionState.STARTED
    assert execution.record.attempts[0].manual_recovery_required
    assert evidence is None
    assert runner.playbook_calls == 1
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1


def test_authorization_drift_and_noncanonical_artifacts_fail_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-storage-prepare-authorization.json"
    )
    value = json.loads(authorization_path.read_text(encoding="utf-8"))
    value["authorization_digest"] = "sha256:" + "e" * 64
    authorization_path.write_bytes(serialize_json(value))
    runner = StoragePrepareRunner()
    with pytest.raises(StatePersistenceError, match="authorization digest conflicts"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
