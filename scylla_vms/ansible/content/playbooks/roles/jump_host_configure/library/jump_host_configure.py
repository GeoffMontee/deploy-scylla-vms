#!/usr/bin/python
"""Atomically install validated jump-host sshd hardening without shell."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

DROP_IN = "/etc/ssh/sshd_config.d/00-deploy-scylla-vms.conf"
COMMAND_TIMEOUT = 15
COMMANDS = {
    "ssh_keygen": "/usr/bin/ssh-keygen",
    "sshd": "/usr/sbin/sshd",
}
HOST_KEY_PUB = {
    "ssh-ed25519": "/etc/ssh/ssh_host_ed25519_key.pub",
    "ecdsa-sha2-nistp256": "/etc/ssh/ssh_host_ecdsa_key.pub",
}
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_KEYGEN_LINE = re.compile(
    r"^\d+\s+(?P<fingerprint>SHA256:[A-Za-z0-9+/]{43})\s+\S.*\((?P<label>ED25519|ECDSA)\)\s*$"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_USER = re.compile(r"[A-Za-z_][A-Za-z0-9._-]{0,31}\Z")
_PERMIT_OPEN = re.compile(
    r"(?:none|\d{1,3}(?:\.\d{1,3}){3}:22(?: \d{1,3}(?:\.\d{1,3}){3}:22)*)\Z"
)
_HEADER = "# Managed by deploy-scylla-vms; local edits are overwritten."
REQUIRED = {
    "PasswordAuthentication": "no",
    "KbdInteractiveAuthentication": "no",
    "ChallengeResponseAuthentication": "no",
    "PermitRootLogin": "no",
    "PubkeyAuthentication": "yes",
    "AuthenticationMethods": "publickey",
    "AllowAgentForwarding": "no",
    "X11Forwarding": "no",
    "PermitTunnel": "no",
    "AllowStreamLocalForwarding": "no",
    "AllowTcpForwarding": "local",
    "GatewayPorts": "no",
    "PermitListen": "none",
    "LogLevel": "VERBOSE",
}
ALLOWED_KEYS = frozenset({*REQUIRED, "PermitOpen", "AllowUsers"})
UNSAFE = (
    "passwordauthentication yes",
    "kbdinteractiveauthentication yes",
    "challengeresponseauthentication yes",
    "permitrootlogin yes",
    "permitrootlogin prohibit-password",
    "permitrootlogin forced-commands-only",
    "permitemptypasswords",
    "pubkeyauthentication no",
    "authenticationmethods password",
    "allowagentforwarding yes",
    "x11forwarding yes",
    "permittunnel yes",
    "allowstreamlocalforwarding yes",
    "allowtcpforwarding yes",
    "allowtcpforwarding all",
    "allowtcpforwarding remote",
    "gatewayports yes",
    "gatewayports clientspecified",
    "permitlisten any",
    "permitopen any",
    "allowusers *",
    "stricthostkeychecking no",
    "authorizedkeyscommand",
)
_ALGORITHM_LABEL = {
    "ssh-ed25519": "ED25519",
    "ecdsa-sha2-nistp256": "ECDSA",
}


class JumpHostConfigureError(Exception):
    def __init__(self, blocker: str) -> None:
        super().__init__(blocker)
        self.blocker = blocker


def _run(argv: list[str], *, blocker: str) -> str:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=COMMAND_TIMEOUT,
            shell=False,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise JumpHostConfigureError(blocker) from error
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 65536:
        raise JumpHostConfigureError(blocker)
    return result.stdout


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_config(config: object, config_digest: object) -> str:
    if not isinstance(config, str) or not config or "\0" in config:
        raise JumpHostConfigureError("sshd-validation-failed")
    if not isinstance(config_digest, str) or _DIGEST.fullmatch(config_digest) is None:
        raise JumpHostConfigureError("sshd-validation-failed")
    if _digest(config) != config_digest:
        raise JumpHostConfigureError("sshd-validation-failed")
    lowered = config.lower()
    if any(option in lowered for option in UNSAFE):
        raise JumpHostConfigureError("sshd-validation-failed")
    lines = config.splitlines()
    if not lines or lines[0] != _HEADER or config[-1] != "\n":
        raise JumpHostConfigureError("sshd-validation-failed")
    parsed: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line.startswith("#") or " " not in line:
            raise JumpHostConfigureError("sshd-validation-failed")
        key, value = line.split(" ", 1)
        if key in parsed or key not in ALLOWED_KEYS or not value or "\t" in line:
            raise JumpHostConfigureError("sshd-validation-failed")
        parsed[key] = value
    if set(parsed) != ALLOWED_KEYS:
        raise JumpHostConfigureError("sshd-validation-failed")
    for key, expected in REQUIRED.items():
        if parsed[key] != expected:
            raise JumpHostConfigureError("sshd-validation-failed")
    if _USER.fullmatch(parsed["AllowUsers"]) is None:
        raise JumpHostConfigureError("sshd-validation-failed")
    permit_open = parsed["PermitOpen"]
    if _PERMIT_OPEN.fullmatch(permit_open) is None:
        raise JumpHostConfigureError("sshd-validation-failed")
    if permit_open != "none":
        routes = permit_open.split(" ")
        if routes != sorted(set(routes)):
            raise JumpHostConfigureError("sshd-validation-failed")
        for route in routes:
            address, port = route.rsplit(":", 1)
            if port != "22":
                raise JumpHostConfigureError("sshd-validation-failed")
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError as error:
                raise JumpHostConfigureError("sshd-validation-failed") from error
            if (
                not isinstance(parsed_address, ipaddress.IPv4Address)
                or not parsed_address.is_private
                or str(parsed_address) != address
            ):
                raise JumpHostConfigureError("sshd-validation-failed")
    return config


def _validate_host_key(
    algorithm: object,
    fingerprint: object,
    *,
    public_key_path: Path,
) -> None:
    if (
        not isinstance(algorithm, str)
        or algorithm not in HOST_KEY_PUB
        or not isinstance(fingerprint, str)
        or _FINGERPRINT.fullmatch(fingerprint) is None
    ):
        raise JumpHostConfigureError("host-key-mismatch")
    try:
        info = public_key_path.lstat()
    except OSError as error:
        raise JumpHostConfigureError("host-key-mismatch") from error
    if not public_key_path.is_file() or info.st_size > 16 * 1024:
        raise JumpHostConfigureError("host-key-mismatch")
    try:
        text = public_key_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise JumpHostConfigureError("host-key-mismatch") from error
    parts = text.split()
    if len(parts) < 2 or parts[0] != algorithm:
        raise JumpHostConfigureError("host-key-mismatch")
    output = _run(
        [COMMANDS["ssh_keygen"], "-l", "-E", "sha256", "-f", str(public_key_path)],
        blocker="host-key-mismatch",
    )
    match = _KEYGEN_LINE.fullmatch(output.splitlines()[0].strip() if output else "")
    if (
        match is None
        or match.group("fingerprint") != fingerprint
        or match.group("label") != _ALGORITHM_LABEL[algorithm]
    ):
        raise JumpHostConfigureError("host-key-mismatch")


def _atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def _restore(path: Path, previous: bytes | None) -> None:
    if previous is None:
        with suppress(FileNotFoundError):
            path.unlink()
        return
    _atomic_write(path, previous)


def apply_hardening(
    *,
    config: object,
    config_digest: object,
    expected_host_key_algorithm: object,
    expected_host_key_fingerprint: object,
    path: object,
    check_mode: bool,
    host_key_path: Path | None = None,
    require_production_path: bool = True,
) -> bool:
    """Validate host keys and install the exact drop-in, restoring on failure."""

    if not isinstance(path, str) or (require_production_path and path != DROP_IN):
        raise JumpHostConfigureError("sshd-validation-failed")
    drop_in = Path(path)
    if drop_in.name != "00-deploy-scylla-vms.conf" or ".." in drop_in.parts:
        raise JumpHostConfigureError("sshd-validation-failed")
    rendered = _validate_config(config, config_digest)
    algorithm = expected_host_key_algorithm
    if not isinstance(algorithm, str) or algorithm not in HOST_KEY_PUB:
        raise JumpHostConfigureError("host-key-mismatch")
    public_key = host_key_path or Path(HOST_KEY_PUB[algorithm])
    _validate_host_key(
        algorithm,
        expected_host_key_fingerprint,
        public_key_path=public_key,
    )
    desired = rendered.encode("utf-8")
    previous: bytes | None = None
    if drop_in.exists():
        try:
            info = drop_in.lstat()
        except OSError as error:
            raise JumpHostConfigureError("sshd-validation-failed") from error
        if not drop_in.is_file() or info.st_size > 65536:
            raise JumpHostConfigureError("sshd-validation-failed")
        previous = drop_in.read_bytes()
        if previous == desired:
            return False
    if check_mode:
        return True
    drop_in.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _atomic_write(drop_in, desired)
    try:
        _run([COMMANDS["sshd"], "-t"], blocker="sshd-validation-failed")
    except JumpHostConfigureError:
        _restore(drop_in, previous)
        raise
    return True


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "config": {"type": "str", "required": True, "no_log": True},
            "config_digest": {"type": "str", "required": True},
            "expected_host_key_algorithm": {"type": "str", "required": True},
            "expected_host_key_fingerprint": {"type": "str", "required": True},
            "path": {"type": "str", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        changed = apply_hardening(
            config=module.params["config"],
            config_digest=module.params["config_digest"],
            expected_host_key_algorithm=module.params["expected_host_key_algorithm"],
            expected_host_key_fingerprint=module.params[
                "expected_host_key_fingerprint"
            ],
            path=module.params["path"],
            check_mode=module.check_mode,
        )
    except JumpHostConfigureError as error:
        module.fail_json(msg=error.blocker, changed=False)
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
