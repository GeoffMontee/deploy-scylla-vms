import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import FakeRunner, _builder, _metadata, _paths
from test_ssh_trust_readiness import (
    _fingerprint,
    _host,
    _inventory,
    _observed,
    _trust,
)

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.jump_host_configure import (
    JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
    JUMP_HOST_SSHD_DROP_IN,
    JumpHostConfigureStatus,
    authorize_jump_host_configuration,
    build_jump_host_configure_payload,
    parse_jump_host_configure_execution,
)
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import PLAYBOOKS, CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError


def _base_os(logical_id: str = "jump-host-1") -> BaseOsEvidence:
    return BaseOsEvidence(
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


def _cluster_inventory():
    jump = _host(
        "jump-host-1",
        HostRole.JUMP_HOST,
        "10.0.0.10",
        public="203.0.113.10",
    )
    scylla = _host(
        "scylla-ad-1-1",
        HostRole.SCYLLA,
        "10.0.0.20",
        jump="jump-host-1",
    )
    manager = _host(
        "manager-1",
        HostRole.MANAGER,
        "10.0.0.30",
        jump="jump-host-1",
    )
    inventory = _inventory((jump, scylla, manager))
    return inventory, _observed(inventory), _trust(inventory)


def _readiness(inventory: object, trust: object) -> ReadinessReport:
    stored_inventory = cast(Any, inventory)
    stored_trust = cast(Any, trust)
    return ReadinessReport(
        EvidenceStatus.FRESH,
        EvidenceStatus.FRESH,
        TrustReadiness.COMPLETE,
        RouteReadiness.VALID,
        stored_inventory.record.source_manifest_generation,
        stored_inventory.record.source_manifest_digest,
        stored_inventory.record.generation,
        stored_inventory.digest,
        stored_trust.record.generation,
        stored_trust.digest,
        len(stored_inventory.record.inventory.hosts),
        len(stored_inventory.record.inventory.hosts),
        (),
        RouteReport(RouteReadiness.VALID, 1, 2, 1, ()),
        tuple((classification, ()) for classification in OperationClassification),
    )


def _context() -> tuple[dict[str, object], object, object, object, object, object]:
    inventory, observed, trust = _cluster_inventory()
    metadata = _metadata()
    readiness = _readiness(inventory, trust)
    authorization = authorize_jump_host_configuration(
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        _base_os(),
        operation_id="op-jump-1",
        target_logical_id="jump-host-1",
    )
    payload = build_jump_host_configure_payload(
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        _base_os(),
        authorization,
    )
    return payload, metadata, observed, inventory, trust, authorization


def _result(payload: dict[str, object], status: str = "changed") -> dict[str, object]:
    success = status in {"changed", "noop"}
    predicted = status != "not-predicted"
    return {
        "allowed_route_digest": payload["allowed_route_digest"],
        "blockers": [] if success or not predicted else ["execution-failed"],
        "config_digest": payload["config_digest"],
        "host_key_digest": payload["host_key_digest"],
        "logical_id": payload["logical_id"],
        "provenance_digests": payload["provenance"],
        "reload_passed": True if status == "changed" else None,
        "reload_performed": status == "changed",
        "schema_version": JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
        "status": status,
        "validation_passed": True if success else None,
        "validation_performed": success,
    }


def _stdout(
    payload: dict[str, object],
    status: str = "changed",
    *,
    failed: int = 0,
    unreachable: int = 0,
    include_marker: bool = True,
) -> str:
    changed = int(status == "changed")
    lines = []
    if include_marker:
        encoded = base64.b64encode(
            json.dumps(_result(payload, status)).encode()
        ).decode()
        lines.append(
            f'ok: [jump-host-1] => {{"msg": "DSV_JUMP_HOST_CONFIGURE_B64={encoded}"}}'
        )
    lines.append("PLAY RECAP *****")
    lines.append(
        f"{payload['logical_id']} : ok=4 changed={changed} unreachable={unreachable} "
        f"failed={failed} skipped=0 rescued=0 ignored=0"
    )
    return "\n".join(lines) + "\n"


def _remote_module() -> object:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/jump_host_configure/library"
        / "jump_host_configure.py"
    )
    spec = importlib.util.spec_from_file_location("jump_host_configure_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_payload_renders_exact_hardening_and_permit_open_routes() -> None:
    payload, *_ = _context()
    config = cast(str, payload["config"])
    assert payload["schema_version"] == JUMP_HOST_CONFIGURE_SCHEMA_VERSION
    assert payload["sshd_drop_in"] == JUMP_HOST_SSHD_DROP_IN
    assert payload["logical_id"] == "jump-host-1"
    assert payload["allowed_routes"] == ["10.0.0.20:22", "10.0.0.30:22"]
    assert payload["network_intent"] == (
        "operator-ssh-to-jump-and-jump-ssh-to-assigned-private-hosts"
    )
    for required in (
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "ChallengeResponseAuthentication no",
        "PermitRootLogin no",
        "PubkeyAuthentication yes",
        "AuthenticationMethods publickey",
        "AllowAgentForwarding no",
        "X11Forwarding no",
        "PermitTunnel no",
        "AllowStreamLocalForwarding no",
        "AllowTcpForwarding local",
        "GatewayPorts no",
        "PermitListen none",
        "PermitOpen 10.0.0.20:22 10.0.0.30:22",
        "AllowUsers opc",
        "LogLevel VERBOSE",
    ):
        assert required in config
    for forbidden in (
        "PasswordAuthentication yes",
        "PermitRootLogin yes",
        "AllowTcpForwarding yes",
        "AllowTcpForwarding all",
        "AllowAgentForwarding yes",
        "X11Forwarding yes",
        "PermitTunnel yes",
        "GatewayPorts yes",
        "PermitOpen any",
        "PermitListen any",
        "AllowUsers *",
        "PermitEmptyPasswords",
        "StrictHostKeyChecking no",
    ):
        assert forbidden.lower() not in config.lower()
    assert hashlib.sha256(config.encode()).hexdigest() == payload["config_digest"][7:]


def test_exact_jump_only_target_refusal() -> None:
    inventory, observed, trust = _cluster_inventory()
    metadata = _metadata()
    readiness = _readiness(inventory, trust)
    with pytest.raises(StateConflictError, match="exact jump ID"):
        authorize_jump_host_configuration(
            metadata,
            observed,
            inventory,
            trust,
            readiness,
            _base_os("scylla-ad-1-1"),
            operation_id="op-jump-1",
            target_logical_id="scylla-ad-1-1",
        )
    with pytest.raises(StateConflictError, match="exact jump ID"):
        authorize_jump_host_configuration(
            metadata,
            observed,
            inventory,
            trust,
            readiness,
            _base_os(),
            operation_id="op-jump-1",
            target_logical_id="jump_hosts",
        )


def test_stale_trust_routes_and_base_evidence_are_refused() -> None:
    inventory, observed, trust = _cluster_inventory()
    metadata = _metadata()
    readiness = _readiness(inventory, trust)
    stale_trust = replace(trust, digest="sha256:" + "b" * 64)
    with pytest.raises(StateConflictError, match="provenance is stale"):
        authorize_jump_host_configuration(
            metadata,
            observed,
            inventory,
            stale_trust,
            readiness,
            _base_os(),
            operation_id="op-jump-1",
            target_logical_id="jump-host-1",
        )
    reboot = BaseOsEvidence(
        BaseOsStatus.REBOOT_REQUIRED,
        (
            BaseOsHostEvidence(
                "jump-host-1",
                BaseOsStatus.REBOOT_REQUIRED,
                True,
                True,
                "reboot-required",
            ),
        ),
    )
    with pytest.raises(StateConflictError, match="base-os evidence"):
        authorize_jump_host_configuration(
            metadata,
            observed,
            inventory,
            trust,
            readiness,
            reboot,
            operation_id="op-jump-1",
            target_logical_id="jump-host-1",
        )
    ipv6_hosts = (
        _host(
            "jump-host-1",
            HostRole.JUMP_HOST,
            "10.0.0.10",
            public="203.0.113.10",
        ),
        _host(
            "scylla-ad-1-1",
            HostRole.SCYLLA,
            "fd12:3456:789a:1::20",
            jump="jump-host-1",
        ),
    )
    ipv6_inventory = _inventory(ipv6_hosts)
    ipv6_observed = _observed(ipv6_inventory)
    ipv6_trust = _trust(ipv6_inventory)
    with pytest.raises(StateConflictError, match="private route"):
        authorize_jump_host_configuration(
            metadata,
            ipv6_observed,
            ipv6_inventory,
            ipv6_trust,
            _readiness(ipv6_inventory, ipv6_trust),
            _base_os(),
            operation_id="op-jump-1",
            target_logical_id="jump-host-1",
        )


@pytest.mark.parametrize(
    ("status", "exit_code", "failed"),
    [
        ("changed", 0, 0),
        ("noop", 0, 0),
        ("not-predicted", 0, 0),
        ("failed", 2, 1),
    ],
)
def test_parser_statuses_and_check_mode(
    status: str, exit_code: int, failed: int
) -> None:
    payload, *_ = _context()
    result = _result(payload, status)
    if status == "failed":
        result["blockers"] = ["reload-failed"]
        result["validation_performed"] = True
        result["validation_passed"] = True
        result["reload_performed"] = True
        result["reload_passed"] = False
        encoded = base64.b64encode(json.dumps(result).encode()).decode()
        stdout = (
            f'ok: [jump-host-1] => {{"msg": "DSV_JUMP_HOST_CONFIGURE_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{payload['logical_id']} : ok=4 changed=0 unreachable=0 failed=1 "
            "skipped=0 rescued=0 ignored=0\n"
        )
    else:
        stdout = _stdout(payload, status, failed=failed)
    evidence = parse_jump_host_configure_execution(
        stdout, expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status is JumpHostConfigureStatus(status)
    assert "10.0.0." not in stdout.split("DSV_JUMP_HOST_CONFIGURE_B64=")[0]


def test_parser_failure_timeout_malformed_and_redaction() -> None:
    payload, *_ = _context()
    failed = parse_jump_host_configure_execution(
        _stdout(payload, "changed", failed=1, include_marker=False),
        expected_payload=payload,
        exit_code=2,
    )
    assert failed.status is JumpHostConfigureStatus.FAILED
    assert failed.blockers == ("execution-failed",)
    with pytest.raises(AnsibleError, match="malformed"):
        parse_jump_host_configure_execution(
            "DSV_JUMP_HOST_CONFIGURE_B64=@@@\nPLAY RECAP *****\n"
            "jump-host-1 : ok=1 changed=0 unreachable=0 failed=1 "
            "skipped=0 rescued=0 ignored=0\n",
            expected_payload=payload,
            exit_code=2,
        )
    oversize = "x" * (512 * 1024 + 1)
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_jump_host_configure_execution(
            oversize, expected_payload=payload, exit_code=2
        )
    secret = _result(payload, "changed")
    secret["blockers"] = ["password=obviously-fake"]
    encoded = base64.b64encode(json.dumps(secret).encode()).decode()
    stdout = (
        f"DSV_JUMP_HOST_CONFIGURE_B64={encoded}\nPLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=1 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="values conflict"):
        parse_jump_host_configure_execution(
            stdout, expected_payload=payload, exit_code=0
        )


def test_remote_module_validates_directives_host_key_atomic_and_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, *_ = _context()
    module = _remote_module()
    config = cast(str, payload["config"])
    module._validate_config(config, payload["config_digest"])
    for unsafe in (
        config.replace("PasswordAuthentication no", "PasswordAuthentication yes"),
        config.replace("PermitRootLogin no", "PermitRootLogin yes"),
        config.replace("AllowTcpForwarding local", "AllowTcpForwarding yes"),
        config.replace("PermitOpen 10.0.0.20:22 10.0.0.30:22", "PermitOpen any"),
        config.replace("AllowUsers opc", "AllowUsers *"),
        config.replace("GatewayPorts no", "GatewayPorts yes"),
        config + "AuthorizedKeysCommand /bin/true\n",
    ):
        digest = "sha256:" + hashlib.sha256(unsafe.encode()).hexdigest()
        with pytest.raises(module.JumpHostConfigureError):
            module._validate_config(unsafe, digest)

    host_key = tmp_path / "ssh_host_ed25519_key.pub"
    algorithm = cast(dict[str, str], payload["host_key"])["algorithm"]
    fingerprint = cast(dict[str, str], payload["host_key"])["fingerprint"]
    public_key = next(
        entry.public_key
        for entry in _trust(_cluster_inventory()[0]).record.entries
        if entry.logical_id == "jump-host-1"
    )
    host_key.write_text(f"{algorithm} {public_key} jump-host-1\n", encoding="utf-8")

    def fake_run(argv: list[str], *, blocker: str) -> str:
        if argv[0] == module.COMMANDS["ssh_keygen"]:
            assert argv == [
                "/usr/bin/ssh-keygen",
                "-l",
                "-E",
                "sha256",
                "-f",
                str(host_key),
            ]
            return f"256 {fingerprint} jump-host-1 (ED25519)\n"
        assert argv == ["/usr/sbin/sshd", "-t"]
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    drop_in = tmp_path / "sshd_config.d" / "00-deploy-scylla-vms.conf"
    drop_in.parent.mkdir()
    assert module.apply_hardening(
        config=config,
        config_digest=payload["config_digest"],
        expected_host_key_algorithm=algorithm,
        expected_host_key_fingerprint=fingerprint,
        path=str(drop_in),
        check_mode=True,
        host_key_path=host_key,
        require_production_path=False,
    )
    assert not drop_in.exists()
    assert module.apply_hardening(
        config=config,
        config_digest=payload["config_digest"],
        expected_host_key_algorithm=algorithm,
        expected_host_key_fingerprint=fingerprint,
        path=str(drop_in),
        check_mode=False,
        host_key_path=host_key,
        require_production_path=False,
    )
    assert drop_in.read_text(encoding="utf-8") == config
    assert drop_in.stat().st_mode & 0o777 == 0o644
    assert not module.apply_hardening(
        config=config,
        config_digest=payload["config_digest"],
        expected_host_key_algorithm=algorithm,
        expected_host_key_fingerprint=fingerprint,
        path=str(drop_in),
        check_mode=False,
        host_key_path=host_key,
        require_production_path=False,
    )
    previous = drop_in.read_text(encoding="utf-8")
    drop_in.write_text("# stale\n", encoding="utf-8")

    def failing_sshd(argv: list[str], *, blocker: str) -> str:
        if argv[0] == module.COMMANDS["ssh_keygen"]:
            return f"256 {fingerprint} jump-host-1 (ED25519)\n"
        raise module.JumpHostConfigureError("sshd-validation-failed")

    monkeypatch.setattr(module, "_run", failing_sshd)
    with pytest.raises(module.JumpHostConfigureError, match="sshd-validation-failed"):
        module.apply_hardening(
            config=config,
            config_digest=payload["config_digest"],
            expected_host_key_algorithm=algorithm,
            expected_host_key_fingerprint=fingerprint,
            path=str(drop_in),
            check_mode=False,
            host_key_path=host_key,
            require_production_path=False,
        )
    assert drop_in.read_text(encoding="utf-8") == "# stale\n"
    drop_in.write_text(previous, encoding="utf-8")
    with pytest.raises(module.JumpHostConfigureError, match="host-key-mismatch"):
        module.apply_hardening(
            config=config,
            config_digest=payload["config_digest"],
            expected_host_key_algorithm=algorithm,
            expected_host_key_fingerprint="SHA256:" + "A" * 43,
            path=str(drop_in),
            check_mode=True,
            host_key_path=host_key,
            require_production_path=False,
        )
    with pytest.raises(module.JumpHostConfigureError, match="sshd-validation-failed"):
        module.apply_hardening(
            config=config,
            config_digest=payload["config_digest"],
            expected_host_key_algorithm=algorithm,
            expected_host_key_fingerprint=fingerprint,
            path="/tmp/00-deploy-scylla-vms.conf",
            check_mode=True,
            host_key_path=host_key,
        )
    assert _fingerprint(public_key) == fingerprint


@pytest.mark.parametrize(
    ("check", "status"), [(False, "changed"), (True, "not-predicted")]
)
def test_service_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path, check: bool, status: str
) -> None:
    payload, metadata, observed, inventory, trust, authorization = _context()
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(
                0, "203.0.113.10 secret-token\n" + _stdout(payload, status), ""
            ),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_jump_host_configure(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            trust,  # type: ignore[arg-type]
            _base_os(),
            authorization,  # type: ignore[arg-type]
            limit=("jump-host-1",),
            readiness=_readiness(inventory, trust),
            check=check,
        )
    assert result.jump_host_configure is not None
    assert result.jump_host_configure.status is JumpHostConfigureStatus(status)
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {
        "deploy_scylla_vms_jump_host_configure": payload
    }
    assert "--limit" in runner.specs[-1].argv
    assert "jump-host-1" in runner.specs[-1].argv
    assert ("--check" in runner.specs[-1].argv) is check
    assert "203.0.113.10" in runner.specs[-1].sensitive_values
    assert "10.0.0.20" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())

    fail_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(
                2, _stdout(payload, "changed", failed=1, include_marker=False), ""
            ),
        ]
    )
    fail_service = AnsibleService(_builder(tmp_path, paths), fail_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        fail_service.version(lock)
        failed = fail_service.execute_jump_host_configure(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            trust,  # type: ignore[arg-type]
            _base_os(),
            authorization,  # type: ignore[arg-type]
            limit=("jump-host-1",),
            readiness=_readiness(inventory, trust),
        )
    assert failed.jump_host_configure is not None
    assert failed.jump_host_configure.status is JumpHostConfigureStatus.FAILED

    timeout_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
        ]
    )
    timeout_service = AnsibleService(_builder(tmp_path, paths), timeout_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        timeout_service.version(lock)
        timeout_runner.error = ProcessTimeoutError("token=obviously-fake")
        with pytest.raises(
            AnsibleError, match="jump-host-configure command failed"
        ) as caught:
            timeout_service.execute_jump_host_configure(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                trust,  # type: ignore[arg-type]
                _base_os(),
                authorization,  # type: ignore[arg-type]
                limit=("jump-host-1",),
                readiness=_readiness(inventory, trust),
            )
    assert "obviously-fake" not in str(caught.value)
    assert not tuple(paths.ansible_local_tmp.iterdir())

    malformed_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, "PLAY RECAP *****\n", ""),
        ]
    )
    malformed_service = AnsibleService(_builder(tmp_path, paths), malformed_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        malformed_service.version(lock)
        with pytest.raises(AnsibleError, match="recap membership conflicts"):
            malformed_service.execute_jump_host_configure(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                trust,  # type: ignore[arg-type]
                _base_os(),
                authorization,  # type: ignore[arg-type]
                limit=("jump-host-1",),
                readiness=_readiness(inventory, trust),
            )


def test_service_refuses_any_limit_except_authorized_jump() -> None:
    *_, authorization = _context()

    class FakeBuilder:
        paths = object()

    class FakeLock:
        def assert_held_for(self, paths: object) -> None:
            assert paths is FakeBuilder.paths

    service = object.__new__(AnsibleService)
    service._builder = FakeBuilder()
    with pytest.raises(StateConflictError, match="one exact jump ID"):
        service.execute_jump_host_configure(
            FakeLock(),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            authorization,
            limit=("scylla-ad-1-1",),
            readiness=cast(object, None),
        )
    with pytest.raises(StateConflictError, match="one exact jump ID"):
        service.execute_jump_host_configure(
            FakeLock(),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            authorization,
            limit=("jump-host-1", "jump-host-2"),
            readiness=cast(object, None),
        )


def test_registry_package_syntax_lint_parity_and_forbidden_actions() -> None:
    definition = get_playbook("jump-host-configure")
    assert definition.source_available
    assert definition.hosts == "jump_hosts"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.MUTATING
    assert callable(AnsibleService.execute_jump_host_configure)
    assert {book.name for book in PLAYBOOKS if book.source_available} >= {
        "jump-host-configure"
    }
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    expected = {
        "playbooks/jump-host-configure.yml",
        "playbooks/roles/jump_host_configure/handlers/main.yml",
        "playbooks/roles/jump_host_configure/library/jump_host_configure.py",
        "playbooks/roles/jump_host_configure/tasks/main.yml",
    }
    assert expected <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    yaml_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "jump-host-configure.yml",
            root / "roles/jump_host_configure/tasks/main.yml",
            root / "roles/jump_host_configure/handlers/main.yml",
        )
    )
    module_text = (
        root / "roles/jump_host_configure/library/jump_host_configure.py"
    ).read_text(encoding="utf-8")
    text = yaml_text + "\n" + module_text
    lowered = text.lower()
    yaml_lowered = yaml_text.lower()
    for required in (
        "serial: 1",
        "any_errors_fatal: true",
        "become: true",
        "hosts: jump_hosts",
        "/usr/sbin/sshd",
        "/usr/bin/ssh-keygen",
        "shell=false",
        "supports_check_mode=true",
        "flush_handlers",
        "name: ssh",
        JUMP_HOST_SSHD_DROP_IN,
        '"allowtcpforwarding": "local"',
        '"permitrootlogin": "no"',
        '"passwordauthentication": "no"',
    ):
        assert required.lower() in lowered
    for forbidden in (
        "ansible.builtin.shell",
        "popen(",
        "start_new_session",
        "stricthostkeychecking=no",
    ):
        assert forbidden not in lowered
    for forbidden in (
        "passwordauthentication yes",
        "permitrootlogin yes",
        "allowtcpforwarding yes",
        "permitopen any",
        "gatewayports yes",
        "allowagentforwarding yes",
    ):
        assert forbidden not in yaml_lowered
    assert "no_log: true" in text


def test_jump_host_configure_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/jump-host-configure.yml"
    )
    local_tmp = tmp_path / "ansible-tmp"
    local_tmp.mkdir()
    result = subprocess.run(
        [
            executable,
            "--syntax-check",
            "-i",
            "localhost,",
            str(playbook),
        ],
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(local_tmp),
            "HOME": str(tmp_path),
        },
    )
    assert result.returncode == 0, result.stderr
    assert "playbook: " in result.stdout
    assert not tuple(local_tmp.iterdir())
