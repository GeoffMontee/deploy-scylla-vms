import json
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_provider_source import _input, _spec

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    TerraformError,
)
from scylla_vms.journal import (
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import ClusterMetadata, ClusterMetadataStore, digest_bytes
from scylla_vms.state import StatePaths, initialize_state_layout
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.inputs import TerraformInputRecord, TerraformInputStore
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    TerraformPlanChangeClass,
    TerraformPlanCheckpointService,
    TerraformPlanCheckpointStore,
    TerraformPlanDriftClass,
    TerraformStatePresence,
    capture_terraform_state_identity,
    parse_terraform_plan_json,
)
from scylla_vms.terraform.source import (
    ApprovedSourceBundle,
    TerraformSourceStager,
)
from scylla_vms.terraform.toolchain import (
    TerraformToolchain,
    TerraformVersion,
)

OPERATION_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
STATE_LINEAGE = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
NOW = datetime(2026, 9, 18, 20, 0, tzinfo=UTC)
REQUEST_DIGEST = digest_bytes(b"redacted deploy request")
SECRET_MARKER = "SHOULD-NOT-PERSIST-secret-value"
ADDRESS_MARKER = "10.0.0.7"


def _paths(tmp_path: Path) -> StatePaths:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    return paths


def _bundle() -> ApprovedSourceBundle:
    return ApprovedSourceBundle.build(
        version="oci-root/v1",
        planning_ready=True,
        files={
            "main.tf": b'terraform { required_version = ">= 1.5.0, < 2.0.0" }\n',
            "variables.tf": (
                b'variable "deploy_scylla_vms_input" { type = any }\n'
                b'variable "deploy_scylla_vms_metadata" { type = any }\n'
            ),
        },
    )


def _change(address: str, actions: list[str]) -> dict[str, object]:
    resource_name = address.rsplit(".", maxsplit=1)[-1]
    return {
        "address": address,
        "change": {
            "actions": actions,
            "after": {"private_ip": ADDRESS_MARKER, "token": SECRET_MARKER},
            "after_sensitive": {"token": True},
            "after_unknown": {},
            "before": None,
            "before_sensitive": {},
        },
        "mode": "managed",
        "name": resource_name,
        "provider_name": "registry.terraform.io/oracle/oci",
        "type": "oci_core_instance",
    }


def _plan_object(
    *,
    resource_changes: list[dict[str, object]] | None = None,
    resource_drift: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "applyable": bool(resource_changes),
        "complete": True,
        "configuration": {
            "provider_config": {
                "oci": {
                    "full_name": "registry.terraform.io/oracle/oci",
                    "name": "oci",
                }
            },
            "root_module": {},
        },
        "errored": False,
        "format_version": "1.2",
        "output_changes": {},
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": 'oci_core_instance.host["scylla-ad-1-1"]',
                        "values": {
                            "private_ip": ADDRESS_MARKER,
                            "token": SECRET_MARKER,
                        },
                    }
                ]
            }
        },
        "prior_state": {
            "format_version": "1.0",
            "terraform_version": "1.6.6",
            "values": {
                "outputs": {"protected": {"value": SECRET_MARKER}},
                "root_module": {},
            },
        },
        "resource_changes": resource_changes or [],
        "resource_drift": resource_drift or [],
        "terraform_version": "1.6.6",
        "variables": {"protected_input": {"value": SECRET_MARKER}},
    }


def _plan_json(
    *,
    resource_changes: list[dict[str, object]] | None = None,
    resource_drift: list[dict[str, object]] | None = None,
) -> str:
    return json.dumps(
        _plan_object(
            resource_changes=resource_changes,
            resource_drift=resource_drift,
        ),
        sort_keys=True,
    )


def _write_owner_file(path: Path, content: str | bytes) -> None:
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    path.chmod(0o600)


def _prepare_foundation(
    tmp_path: Path,
    paths: StatePaths,
    lock: ClusterLock,
    *,
    write_state: bool = True,
) -> None:
    spec = _spec(tmp_path)
    metadata = ClusterMetadata.create(
        cluster_uuid=spec.cluster_uuid,
        cluster_name=spec.cluster_name,
        provider=spec.provider,
        request_digest=REQUEST_DIGEST,
        desired_spec=spec,
        clock=lambda: NOW,
    )
    ClusterMetadataStore(paths).write_locked(
        metadata,
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )
    terraform_input = _input(tmp_path)
    TerraformInputStore(paths).write_locked(
        TerraformInputRecord.create(terraform_input, clock=lambda: NOW),
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )
    TerraformSourceStager(paths).stage_locked(
        _bundle(),
        cluster_uuid=spec.cluster_uuid,
        cluster_name=spec.cluster_name,
        clock=lambda: NOW,
        lock=lock,
    )
    journal = OperationRecord.create_initial_plan(
        operation_id=OPERATION_ID,
        operation="deploy",
        cluster_uuid=spec.cluster_uuid,
        cluster_name=spec.cluster_name,
        request_digest=REQUEST_DIGEST,
        clock=lambda: NOW,
    )
    OperationJournalStore(paths, OPERATION_ID).write(
        journal,
        expected_generation=0,
        expected_digest=None,
    )
    if write_state:
        _write_owner_file(
            paths.terraform_state,
            json.dumps(
                {
                    "lineage": STATE_LINEAGE,
                    "resources": [
                        {"instances": [{"attributes": {"token": SECRET_MARKER}}]}
                    ],
                    "serial": 7,
                    "terraform_version": "1.6.6",
                    "version": 4,
                },
                sort_keys=True,
            ),
        )
    _write_owner_file(
        paths.terraform_plans / f"{OPERATION_ID}.tfplan",
        b"binary saved plan containing SHOULD-NOT-PERSIST-secret-value",
    )


def _toolchain() -> TerraformToolchain:
    return TerraformToolchain(TerraformVersion(1, 6, 6))


def test_plan_json_classifies_destructive_scope_and_drift_without_values() -> None:
    plan_json = _plan_json(
        resource_changes=[
            _change("oci_core_instance.created", ["create"]),
            _change("oci_core_instance.updated", ["update"]),
            _change("oci_core_instance.deleted", ["delete"]),
            _change("oci_core_instance.replaced", ["delete", "create"]),
        ],
        resource_drift=[
            _change("oci_core_instance.drifted", ["create", "delete"]),
        ],
    )

    summary, plan_json_digest = parse_terraform_plan_json(plan_json)

    assert summary.change_class is TerraformPlanChangeClass.DESTRUCTIVE
    assert summary.drift_class is TerraformPlanDriftClass.CONFLICT
    assert summary.resource_changes.create == 1
    assert summary.resource_changes.update == 1
    assert summary.resource_changes.delete == 1
    assert summary.resource_changes.replace == 1
    assert summary.resource_drift.replace == 1
    assert plan_json_digest == digest_bytes(plan_json.encode())
    rendered = json.dumps(summary.to_object(), sort_keys=True)
    assert SECRET_MARKER not in rendered
    assert ADDRESS_MARKER not in rendered
    assert "oci_core_instance" not in rendered


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: {**value, "unexpected": True},
        lambda value: {**value, "complete": False},
        lambda value: {**value, "applyable": False},
        lambda value: {
            **value,
            "resource_changes": [_change("oci_core_instance.bad", ["forget"])],
        },
        lambda value: {**value, "deferred_changes": [{"reason": "unknown"}]},
        lambda value: {**value, "checks": [{"status": "pass"}]},
        lambda value: {**value, "format_version": "1.3"},
        lambda value: {
            key: item for key, item in value.items() if key != "prior_state"
        },
        lambda value: {
            **value,
            "configuration": {"provider_config": {}},
        },
        lambda value: {
            **value,
            "planned_values": {},
        },
        lambda value: {
            **value,
            "prior_state": {
                "format_version": "1.0",
                "terraform_version": "1.7.0",
                "values": {},
            },
        },
    ],
)
def test_plan_json_refuses_unknown_incomplete_or_unsupported_plans(
    mutate: Callable[[dict[str, object]], dict[str, object]],
) -> None:
    value = _plan_object(
        resource_changes=[_change("oci_core_instance.created", ["create"])]
    )
    with pytest.raises(TerraformError):
        parse_terraform_plan_json(json.dumps(mutate(value)))


def test_plan_json_refuses_duplicate_fields() -> None:
    with pytest.raises(TerraformError, match="malformed"):
        parse_terraform_plan_json(
            '{"format_version":"1.2","format_version":"1.2",'
            '"terraform_version":"1.6.6"}'
        )


def test_absent_initial_state_has_an_explicit_redacted_identity(tmp_path: Path) -> None:
    paths = _paths(tmp_path)

    identity = capture_terraform_state_identity(paths)

    assert identity.presence is TerraformStatePresence.ABSENT
    assert identity.serial is None
    assert identity.lineage_digest is None
    assert identity.state_digest is None


def test_capture_persists_redacted_immutable_checkpoint_and_revalidates(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    service = TerraformPlanCheckpointService(paths)
    plan_json = _plan_json(
        resource_changes=[
            _change('oci_core_instance.host["scylla-ad-1-1"]', ["create"])
        ]
    )

    with ClusterLock(paths, "deploy", 0) as lock:
        _prepare_foundation(tmp_path, paths, lock)
        report = service.capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=lock,
        )
        stored = TerraformPlanCheckpointStore(paths, OPERATION_ID).read(
            expected_cluster_uuid=_spec(tmp_path).cluster_uuid,
            expected_cluster_name="example",
            expected_operation="deploy",
        )
        revalidated = service.revalidate_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            lock=lock,
        )

        journal_store = OperationJournalStore(paths, OPERATION_ID)
        initial = journal_store.read(
            expected_cluster_uuid=stored.record.cluster_uuid,
            expected_cluster_name="example",
        )
        planned = initial.record.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            evidence=(
                CheckpointEvidence(
                    OperationPhase.PLAN,
                    EvidenceResult.VALIDATED,
                    report.checkpoint_digest,
                    "terraform-plan-reviewed",
                ),
            ),
            clock=lambda: NOW,
        )
        journal_store.write(
            planned,
            expected_generation=initial.record.generation,
            expected_digest=initial.digest,
        )
        advanced = service.revalidate_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            lock=lock,
        )

    checkpoint_path = paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    persisted = checkpoint_path.read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)
    assert stored.record.schema_version == TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    assert report.schema_version == TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    assert report.summary.change_class is TerraformPlanChangeClass.CREATE_ONLY
    assert report.summary.drift_class is TerraformPlanDriftClass.NONE
    assert report.state_identity.presence is TerraformStatePresence.PRESENT
    assert report.state_identity.serial == 7
    assert report.to_object()["apply_command_available"] is False
    assert revalidated == report
    assert advanced == report
    assert stored.record.checkpoint_digest == report.checkpoint_digest
    assert stored.record.journal_digest == report.journal_digest
    assert checkpoint_path.parent == paths.terraform_plans
    if os.name == "posix":
        assert checkpoint_path.stat().st_mode & 0o777 == 0o600
    for protected in (
        SECRET_MARKER,
        ADDRESS_MARKER,
        STATE_LINEAGE,
        str(tmp_path),
        "oci_core_instance",
    ):
        assert protected not in persisted
        assert protected not in projected


def test_capture_binds_an_absent_initial_deploy_state(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    service = TerraformPlanCheckpointService(paths)
    plan_json = _plan_json(
        resource_changes=[_change("oci_core_instance.created", ["create"])]
    )

    with ClusterLock(paths, "deploy", 0) as lock:
        _prepare_foundation(tmp_path, paths, lock, write_state=False)
        report = service.capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=lock,
        )

    assert report.state_identity.presence is TerraformStatePresence.ABSENT
    assert report.state_identity.serial is None


def test_revalidation_refuses_saved_plan_state_and_json_drift(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    service = TerraformPlanCheckpointService(paths)
    original_json = _plan_json(
        resource_changes=[_change("oci_core_instance.created", ["create"])]
    )
    changed_json = _plan_json(
        resource_changes=[_change("oci_core_instance.updated", ["update"])]
    )

    with ClusterLock(paths, "deploy", 0) as lock:
        _prepare_foundation(tmp_path, paths, lock)
        service.capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=original_json,
            clock=lambda: NOW,
            lock=lock,
        )
        with pytest.raises(StateConflictError, match="stale or changed"):
            service.revalidate_locked(
                operation_id=OPERATION_ID,
                operation="deploy",
                toolchain=_toolchain(),
                plan_json=changed_json,
                lock=lock,
            )

        _write_owner_file(
            paths.terraform_plans / f"{OPERATION_ID}.tfplan",
            b"tampered saved plan",
        )
        with pytest.raises(StateConflictError, match="stale or changed"):
            service.revalidate_locked(
                operation_id=OPERATION_ID,
                operation="deploy",
                toolchain=_toolchain(),
                plan_json=original_json,
                lock=lock,
            )


def test_capture_requires_matching_operation_lock_and_is_create_only(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    service = TerraformPlanCheckpointService(paths)
    plan_json = _plan_json(
        resource_changes=[_change("oci_core_instance.created", ["create"])]
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        _prepare_foundation(tmp_path, paths, lock)

    with (
        ClusterLock(paths, "redeploy", 0) as wrong_lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        service.capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=wrong_lock,
        )
    assert not (paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json").exists()

    with ClusterLock(paths, "deploy", 0) as lock:
        service.capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=lock,
        )
        with pytest.raises(StatePersistenceError, match="absent generation one"):
            service.capture_locked(
                operation_id=OPERATION_ID,
                operation="deploy",
                toolchain=_toolchain(),
                plan_json=plan_json,
                clock=lambda: NOW,
                lock=lock,
            )


def test_apply_and_destroy_remain_absent_from_command_boundary(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    executable = tmp_path / "terraform"
    _write_owner_file(executable, "#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    builder = TerraformCommandBuilder(executable, paths)

    assert not hasattr(builder, "apply")
    assert not hasattr(builder, "destroy")
