import json
from pathlib import Path

import pytest
from test_ansible import (
    FakeRunner,
    _builder,
    _inventory,
    _metadata,
    _paths,
    _readiness,
)

from scylla_vms.ansible.orchestration import (
    ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
    AnsibleOperationPlanStatus,
    AnsibleOperationStepStatus,
    AnsibleStepIntent,
    ansible_operation_plan_checkpoint_evidence,
    validate_operation_playbook_catalog,
)
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    OperationPlaybookStep,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError, StateLockError
from scylla_vms.journal import EvidenceResult, OperationPhase
from scylla_vms.locking import ClusterLock


def _check_intents() -> tuple[AnsibleStepIntent, ...]:
    return (
        AnsibleStepIntent(1, ("jump-host-1",), {}, check=True),
        AnsibleStepIntent(
            2,
            ("jump-host-1",),
            {
                "deploy_scylla_vms_connect_timeout_seconds": 2.5,
                "deploy_scylla_vms_destination_probes": [],
                "deploy_scylla_vms_probe_timeout_seconds": 3,
            },
            check=True,
        ),
    )


def test_offline_operation_plan_is_lock_bound_redacted_and_journal_compatible(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    runner = FakeRunner()
    service = AnsibleService(_builder(tmp_path, paths), runner)

    lock = ClusterLock(paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        service.plan_operation(
            lock,
            _metadata(),
            inventory,
            "check-jump-hosts",
            readiness=_readiness(inventory),
            active_conditions=(),
            intents=_check_intents(),
        )

    with lock:
        plan = service.plan_operation(
            lock,
            _metadata(),
            inventory,
            "check-jump-hosts",
            readiness=_readiness(inventory),
            active_conditions=(),
            intents=_check_intents(),
        )

    assert plan.schema_version == ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION
    assert plan.status is AnsibleOperationPlanStatus.READY
    assert [step.status for step in plan.steps] == [
        AnsibleOperationStepStatus.READY,
        AnsibleOperationStepStatus.READY,
    ]
    assert plan.steps[1].variable_names == (
        "deploy_scylla_vms_connect_timeout_seconds",
        "deploy_scylla_vms_destination_probes",
        "deploy_scylla_vms_probe_timeout_seconds",
    )
    checkpoint = ansible_operation_plan_checkpoint_evidence(plan)
    assert checkpoint.phase is OperationPhase.PLAN
    assert checkpoint.result is EvidenceResult.VALIDATED
    assert checkpoint.digest == plan.plan_digest
    assert runner.specs == []
    assert not tuple(paths.ansible_local_tmp.iterdir())

    public = json.dumps(plan.to_public_object(), sort_keys=True)
    assert plan.plan_digest in public
    assert "jump-host-1" in public
    for protected in (
        "203.0.113.10",
        "10.0.0.10",
        "ocid1.instance.oc1.iad.fakejump",
        str(paths.cluster_root),
        '"2.5"',
    ):
        assert protected not in public


def test_plan_preserves_unimplemented_operation_and_readiness_blockers(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    runner = FakeRunner()
    service = AnsibleService(_builder(tmp_path, paths), runner)

    with ClusterLock(paths, "deploy", 0) as lock:
        deploy = service.plan_operation(
            lock,
            _metadata(),
            inventory,
            "deploy",
            readiness=_readiness(inventory),
            active_conditions=(),
            intents=(),
        )
        check = service.plan_operation(
            lock,
            _metadata(),
            inventory,
            "check-jump-hosts",
            readiness=_readiness(inventory, blockers=("trust-incomplete",)),
            active_conditions=(),
            intents=_check_intents(),
        )

    assert deploy.status is AnsibleOperationPlanStatus.BLOCKED
    assert "operation-workflow-unavailable" in deploy.blockers
    assert "selected-step-blocked" in deploy.blockers
    assert any(
        "step-intent-missing" in step.blockers
        for step in deploy.steps
        if step.status is AnsibleOperationStepStatus.BLOCKED
    )
    assert check.steps[0].status is AnsibleOperationStepStatus.READY
    assert check.steps[1].status is AnsibleOperationStepStatus.BLOCKED
    assert check.steps[1].blockers == ("readiness-trust-incomplete",)
    checkpoint = ansible_operation_plan_checkpoint_evidence(check)
    assert checkpoint.result is EvidenceResult.FAILED
    assert runner.specs == []


def test_operation_plan_refuses_unknown_conflicting_or_unselected_conditions(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    service = AnsibleService(_builder(tmp_path, paths), FakeRunner())

    with ClusterLock(paths, "deploy", 0) as lock:
        with pytest.raises(AnsibleError, match="not registry-approved"):
            service.plan_operation(
                lock,
                _metadata(),
                inventory,
                "deploy",
                readiness=_readiness(inventory),
                active_conditions=("unknown-branch",),
                intents=(),
            )
        with pytest.raises(AnsibleError, match="mutually exclusive"):
            service.plan_operation(
                lock,
                _metadata(),
                inventory,
                "upgrade-os",
                readiness=_readiness(inventory),
                active_conditions=("in-place", "reprovision"),
                intents=(),
            )
        with pytest.raises(AnsibleError, match="does not match"):
            service.plan_operation(
                lock,
                _metadata(),
                inventory,
                "deploy",
                readiness=_readiness(inventory),
                active_conditions=(),
                intents=(
                    AnsibleStepIntent(
                        3,
                        ("jump-host-1",),
                        {},
                        check=True,
                    ),
                ),
            )


def test_operation_plan_reuses_builder_limit_mode_and_variable_guards(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    service = AnsibleService(_builder(tmp_path, paths), FakeRunner())

    with ClusterLock(paths, "check-jump-hosts", 0) as lock:
        unchecked = service.plan_operation(
            lock,
            _metadata(),
            inventory,
            "check-jump-hosts",
            readiness=_readiness(inventory),
            active_conditions=(),
            intents=(
                AnsibleStepIntent(1, ("jump-host-1",), {}),
                AnsibleStepIntent(2, ("jump-host-1",), {}),
            ),
        )
        assert all(
            "read-only-check-mode-required" in step.blockers for step in unchecked.steps
        )
        with pytest.raises(StateConflictError, match="unknown stable"):
            service.plan_operation(
                lock,
                _metadata(),
                inventory,
                "check-jump-hosts",
                readiness=_readiness(inventory),
                active_conditions=(),
                intents=(
                    AnsibleStepIntent(1, ("unknown-host",), {}, check=True),
                    _check_intents()[1],
                ),
            )
        with pytest.raises(AnsibleError, match="not allowlisted"):
            service.plan_operation(
                lock,
                _metadata(),
                inventory,
                "check-jump-hosts",
                readiness=_readiness(inventory),
                active_conditions=(),
                intents=(
                    _check_intents()[0],
                    AnsibleStepIntent(
                        2,
                        ("jump-host-1",),
                        {"password": "obviously-fake"},
                        check=True,
                    ),
                ),
            )


def test_catalog_validation_rejects_mutating_read_only_mapping() -> None:
    validate_operation_playbook_catalog()
    mappings = dict(OPERATION_PLAYBOOKS)
    mappings["check-jump-hosts"] = (
        OperationPlaybookStep("inventory-preflight"),
        OperationPlaybookStep("base-os"),
    )
    with pytest.raises(AnsibleError, match="read-only operation"):
        validate_operation_playbook_catalog(mappings)
