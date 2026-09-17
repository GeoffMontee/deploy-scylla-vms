"""Immutable operation registry and safety metadata."""

from dataclasses import dataclass
from enum import StrEnum


class OperationClassification(StrEnum):
    """The highest static safety class of an operation."""

    READ_ONLY = "read-only"
    MUTATING = "mutating"
    SENSITIVE = "sensitive"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True, slots=True)
class OperationDefinition:
    """Foundation metadata for one public operation."""

    name: str
    classification: OperationClassification
    summary: str
    implemented: bool = False


OPERATIONS: tuple[OperationDefinition, ...] = (
    OperationDefinition(
        "deploy",
        OperationClassification.MUTATING,
        "Create and configure a new cluster (not implemented).",
    ),
    OperationDefinition(
        "add-node",
        OperationClassification.MUTATING,
        "Add one stable ScyllaDB node (not implemented).",
    ),
    OperationDefinition(
        "replace-node",
        OperationClassification.DESTRUCTIVE,
        "Replace one failed ScyllaDB node (not implemented).",
    ),
    OperationDefinition(
        "destroy-node",
        OperationClassification.DESTRUCTIVE,
        "Safely remove one ScyllaDB node (not implemented).",
    ),
    OperationDefinition(
        "destroy",
        OperationClassification.DESTRUCTIVE,
        "Destroy a complete cluster (not implemented).",
    ),
    OperationDefinition(
        "scale-out",
        OperationClassification.MUTATING,
        "Increase desired ScyllaDB node counts (not implemented).",
    ),
    OperationDefinition(
        "scale-in",
        OperationClassification.DESTRUCTIVE,
        "Safely reduce ScyllaDB node counts (not implemented).",
    ),
    OperationDefinition(
        "redeploy",
        OperationClassification.SENSITIVE,
        "Reconcile a bounded cluster scope (not implemented).",
    ),
    OperationDefinition(
        "refresh-monitoring",
        OperationClassification.MUTATING,
        "Refresh monitoring configuration (not implemented).",
    ),
    OperationDefinition(
        "upgrade-os",
        OperationClassification.SENSITIVE,
        "Perform a rolling operating-system upgrade (not implemented).",
    ),
    OperationDefinition(
        "check-jump-hosts",
        OperationClassification.READ_ONLY,
        "Check validated jump-host connectivity without mutation.",
        implemented=True,
    ),
    OperationDefinition(
        "show",
        OperationClassification.READ_ONLY,
        "Show a redacted report from validated local state.",
        implemented=True,
    ),
)


def get_operation(name: str) -> OperationDefinition:
    """Return an operation definition by its exact public name."""

    for operation in OPERATIONS:
        if operation.name == name:
            return operation
    raise KeyError(name)
