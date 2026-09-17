import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, _readiness
from test_ansible_storage import (
    _postcheck_context,
    _postcheck_result,
    _postcheck_stdout,
)

import scylla_vms.ansible.scylla_install as scylla_install_module
from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.registry import CheckMode, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_INSTALL_SCHEMA_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_ROLE_COMMIT,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_RESOURCE,
    ScyllaInstallStatus,
    build_scylla_install_payload,
    load_scylla_signing_key,
    parse_scylla_install_execution,
    validate_scylla_signing_key,
)
from scylla_vms.ansible.storage_postcheck import parse_storage_postcheck_execution
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError

VERSION = "2026.2.1-0.20260915.abcdef123456-1"


def _context() -> tuple[dict[str, object], BaseOsEvidence]:
    metadata, observed, inventory, *_, postcheck_payload = _postcheck_context()
    logical_id = cast(str, postcheck_payload["logical_id"])
    storage = parse_storage_postcheck_execution(
        _postcheck_stdout(_postcheck_result(postcheck_payload)),
        expected_payload=postcheck_payload,
        exit_code=0,
    )
    base_os = BaseOsEvidence(
        BaseOsStatus.NO_CHANGE,
        (
            BaseOsHostEvidence(
                logical_id,
                BaseOsStatus.NO_CHANGE,
                False,
                False,
                "already-current",
            ),
        ),
    )
    payload = build_scylla_install_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        base_os,
        storage,
        logical_id=logical_id,
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        package_version=VERSION,
        cluster_spec_digest=DIGEST,
    )
    return payload, base_os


def _result(payload: dict[str, object], status: str = "no-change") -> dict[str, object]:
    success = status in {"installed", "no-change"}
    return {
        "blockers": [] if status != "failed" else ["execution-failed"],
        "configuration_performed": False if success else None,
        "installed_edition": payload["edition"] if success else None,
        "installed_version": payload["package_version"] if success else None,
        "logical_id": payload["logical_id"],
        "manager_operation_performed": False if success else None,
        "packages": (
            {name: payload["package_version"] for name in SCYLLA_PACKAGES}
            if success
            else {}
        ),
        "provenance": payload["provenance"],
        "repository_digest": cast(dict[str, object], payload["repository"])[
            "definition_digest"
        ],
        "requested_edition": payload["edition"],
        "requested_version": payload["package_version"],
        "schema_version": SCYLLA_INSTALL_SCHEMA_VERSION,
        "service_inactive": True if success else None,
        "service_masked": True if success else None,
        "service_started": False if success else None,
        "signing_key_digest": cast(dict[str, object], payload["signing_key"])[
            "artifact_digest"
        ],
        "signing_key_fingerprint": cast(dict[str, object], payload["signing_key"])[
            "fingerprint"
        ],
        "status": status,
        "storage_mutation_performed": False if success else None,
        "tuning_performed": False if success else None,
    }


def _stdout(
    payload: dict[str, object],
    status: str = "no-change",
    *,
    failed: int = 0,
) -> str:
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    changed = 1 if status == "installed" else 0
    return (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_SCYLLA_INSTALL_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_scylla_install_payload_is_exact_and_rejects_unsafe_versions() -> None:
    payload, _ = _context()
    assert payload["release_line"] == "2026.2"
    assert payload["edition"] == "enterprise"
    assert payload["channel"] == "stable"
    assert payload["packages"] == list(SCYLLA_PACKAGES)
    assert (
        cast(dict[str, object], payload["signing_key"])["fingerprint"]
        == SCYLLA_SIGNING_KEY_FINGERPRINT
    )
    assert payload["upstream_role_commit"] == SCYLLA_ROLE_COMMIT

    metadata, observed, inventory, *_, postcheck_payload = _postcheck_context()
    storage = parse_storage_postcheck_execution(
        _postcheck_stdout(_postcheck_result(postcheck_payload)),
        expected_payload=postcheck_payload,
        exit_code=0,
    )
    logical_id = cast(str, postcheck_payload["logical_id"])
    _, base_os = _context()
    for version in ("latest", "2026.2", "2026.3.1-0.20260915.abcdef123456-1"):
        with pytest.raises(AnsibleError, match=r"exact 2026\.2"):
            build_scylla_install_payload(
                metadata,
                observed,
                inventory,
                _readiness(inventory),
                base_os,
                storage,
                logical_id=logical_id,
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=version,
                cluster_spec_digest=DIGEST,
            )


def test_scylla_signing_key_bytes_fingerprint_digest_and_tamper_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = load_scylla_signing_key()
    validate_scylla_signing_key(key)
    assert SCYLLA_SIGNING_KEY_DIGEST == (
        "sha256:f2f1f4368a71820ea1f5e4e8900e59ddeec1e78cf98450f3ac84826c828ea417"
    )
    assert SCYLLA_SIGNING_KEY_FINGERPRINT == (
        "6C6ECC84F42AF147BD2A65AEC503C686B007F39E"
    )
    assert SCYLLA_SIGNING_KEY_RESOURCE.endswith("/scylladb-2026.asc")
    with pytest.raises(AnsibleError, match="digest conflicts"):
        validate_scylla_signing_key(key + b"\n")
    monkeypatch.setattr(
        scylla_install_module,
        "SCYLLA_SIGNING_KEY_FINGERPRINT",
        "0" * 40,
    )
    with pytest.raises(AnsibleError, match="identity conflicts"):
        validate_scylla_signing_key(key)


def test_scylla_install_requires_current_base_os_storage_and_provenance() -> None:
    payload, base_os = _context()
    assert payload
    metadata, observed, inventory, *_, postcheck_payload = _postcheck_context()
    storage = parse_storage_postcheck_execution(
        _postcheck_stdout(_postcheck_result(postcheck_payload)),
        expected_payload=postcheck_payload,
        exit_code=0,
    )
    logical_id = cast(str, postcheck_payload["logical_id"])
    reboot = BaseOsEvidence(
        BaseOsStatus.REBOOT_REQUIRED,
        (
            replace(
                base_os.hosts[0],
                status=BaseOsStatus.REBOOT_REQUIRED,
                reboot_required=True,
            ),
        ),
    )
    for changed_base, changed_storage, readiness in (
        (reboot, storage, _readiness(inventory)),
        (base_os, replace(storage, readiness_for_scylla=False), _readiness(inventory)),
        (
            base_os,
            storage,
            replace(_readiness(inventory), trust_digest=None),
        ),
    ):
        with pytest.raises(StateConflictError):
            build_scylla_install_payload(
                metadata,
                observed,
                inventory,
                readiness,
                changed_base,
                changed_storage,
                logical_id=logical_id,
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        ("installed", 0, ScyllaInstallStatus.INSTALLED),
        ("no-change", 0, ScyllaInstallStatus.NO_CHANGE),
        ("not-predicted", 0, ScyllaInstallStatus.NOT_PREDICTED),
        ("failed", 2, ScyllaInstallStatus.FAILED),
    ],
)
def test_scylla_install_result_parser_statuses(
    status: str, exit_code: int, expected: ScyllaInstallStatus
) -> None:
    payload, _ = _context()
    result = _result(payload, status)
    if status == "not-predicted":
        result.update(
            {
                "blockers": [],
                "installed_edition": None,
                "installed_version": None,
                "packages": {},
                "service_inactive": None,
                "service_masked": None,
                "configuration_performed": None,
                "storage_mutation_performed": None,
                "tuning_performed": None,
                "manager_operation_performed": None,
                "service_started": None,
            }
        )
    encoded = base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode()
    changed = 1 if status == "installed" else 0
    failed = 1 if status == "failed" else 0
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_SCYLLA_INSTALL_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_scylla_install_execution(
        stdout, expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status is expected


def test_scylla_install_parser_refuses_malformed_oversize_and_conflicts() -> None:
    payload, _ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_scylla_install_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_scylla_install_execution(
            _stdout(payload, "no-change", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_scylla_install_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is ScyllaInstallStatus.FAILED
    assert evidence.blockers == ("execution-failed",)


def test_scylla_install_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("scylla-install")
    assert definition.source_available
    assert definition.hosts == "scylla"
    assert definition.serial == 1
    assert definition.limit_policy.value == "single-logical-host"
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.tags == (
        "scylla-install",
        "preflight",
        "packages",
        "verify",
    )
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/scylla-install.yml").read_text(encoding="utf-8")
    requirements = (root / "requirements.yml").read_text(encoding="utf-8")
    provenance = (
        root / "playbooks/roles/scylla_install/files/scylladb-2026-key.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "ansible.builtin.copy:",
        "ansible.builtin.deb822_repository:",
        "ansible.builtin.apt:",
        "policy_rc_d: 101",
        "masked: true",
        "state: stopped",
        "signed_by: /etc/apt/keyrings/scylladb-2026.asc",
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST,
    ):
        assert required in playbook
    for forbidden in (
        "ansible.builtin.shell",
        "ansible.builtin.get_url",
        "apt_key",
        "keyserver",
        "curl",
        "wget",
        "http://",
        "state: started",
        "latest",
        "scylla_setup",
        "scylla.yaml",
        "seeds",
        "snitch",
        "manager_enabled",
        "selinux",
        "reboot:",
        "validate_certs: false",
        "trusted=yes",
    ):
        assert forbidden not in playbook.lower()
    assert SCYLLA_ROLE_COMMIT in requirements
    assert "scylladb.scylla_node" in requirements
    assert "role: scylladb.scylla_node" not in playbook
    for required in (
        'retrieved_at: "2026-09-17"',
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST.removeprefix("sha256:"),
        "github.com/scylladb/scylladb/blob/",
        "signed_inrelease:",
        "Refuse any key-revocation",
    ):
        assert required in provenance
