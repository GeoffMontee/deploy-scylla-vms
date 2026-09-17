from scylla_vms.operations import (
    OPERATIONS,
    OperationClassification,
    get_operation,
)
from scylla_vms.providers import PROVIDERS, get_provider, provider_names


def test_operation_registry_is_complete_and_unique() -> None:
    expected = {
        "deploy",
        "add-node",
        "replace-node",
        "destroy-node",
        "destroy",
        "scale-out",
        "scale-in",
        "redeploy",
        "refresh-monitoring",
        "upgrade-os",
        "check-jump-hosts",
        "show",
    }

    assert {operation.name for operation in OPERATIONS} == expected
    assert len(OPERATIONS) == len(expected)
    assert {operation.name for operation in OPERATIONS if operation.implemented} == {
        "check-jump-hosts",
        "show",
    }


def test_operation_classifications_are_conservative() -> None:
    expected = {
        "deploy": OperationClassification.MUTATING,
        "add-node": OperationClassification.MUTATING,
        "replace-node": OperationClassification.DESTRUCTIVE,
        "destroy-node": OperationClassification.DESTRUCTIVE,
        "destroy": OperationClassification.DESTRUCTIVE,
        "scale-out": OperationClassification.MUTATING,
        "scale-in": OperationClassification.DESTRUCTIVE,
        "redeploy": OperationClassification.SENSITIVE,
        "refresh-monitoring": OperationClassification.MUTATING,
        "upgrade-os": OperationClassification.SENSITIVE,
        "check-jump-hosts": OperationClassification.READ_ONLY,
        "show": OperationClassification.READ_ONLY,
    }

    assert {
        operation.name: operation.classification for operation in OPERATIONS
    } == expected
    assert get_operation("show").classification is OperationClassification.READ_ONLY


def test_only_oci_provider_is_accepted() -> None:
    assert len(PROVIDERS) == 1
    assert provider_names() == ("oci",)
    assert get_provider("oci").display_name == "Oracle Cloud Infrastructure"
