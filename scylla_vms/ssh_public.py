"""Strict reading and validation for non-secret OpenSSH public keys."""

import base64
import binascii
import os
import stat
from pathlib import Path

from scylla_vms.errors import ConfigurationError, UnsafePathError

MAXIMUM_PUBLIC_KEY_BYTES = 16 * 1024
_ALGORITHMS = frozenset(
    {
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "ssh-ed25519",
        "ssh-rsa",
    }
)


def read_public_ssh_key(path: Path) -> str:
    """Read one explicitly configured public-key file without following links."""

    if not path.is_absolute() or path.resolve(strict=False) != path:
        raise UnsafePathError("SSH public-key path must be canonical and absolute")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise UnsafePathError("cannot safely open SSH public-key file") from error
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise UnsafePathError(
                "SSH public-key file must be a singly linked regular file"
            )
        if os.name == "posix":
            getuid = getattr(os, "geteuid", None)
            if getuid is not None and opened.st_uid != getuid():
                raise UnsafePathError("SSH public-key file has an unexpected owner")
            if stat.S_IMODE(opened.st_mode) & 0o022:
                raise UnsafePathError(
                    "SSH public-key file must not be group/other writable"
                )
        data = os.read(descriptor, MAXIMUM_PUBLIC_KEY_BYTES + 1)
        if len(data) > MAXIMUM_PUBLIC_KEY_BYTES:
            raise ConfigurationError("SSH public-key file exceeds the size limit")
        if os.read(descriptor, 1):
            raise ConfigurationError("SSH public-key file exceeds the size limit")
    finally:
        os.close(descriptor)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ConfigurationError("SSH public-key file is not valid UTF-8") from error
    return validate_public_ssh_key_text(text)


def validate_public_ssh_key_text(value: str) -> str:
    """Validate one canonical OpenSSH public-key line and return it unchanged."""

    if "PRIVATE KEY" in value.upper():
        raise ConfigurationError("private SSH key material is forbidden")
    if "\x00" in value or "\r" in value:
        raise ConfigurationError("SSH public key contains invalid characters")
    line = value[:-1] if value.endswith("\n") else value
    if "\n" in line or not line or line != line.strip():
        raise ConfigurationError("SSH public-key file must contain exactly one line")
    parts = line.split(" ", 2)
    if len(parts) < 2 or parts[0] not in _ALGORITHMS or not parts[1]:
        raise ConfigurationError("SSH public-key syntax is unsupported")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as error:
        raise ConfigurationError("SSH public-key payload is invalid") from error
    fields = _wire_fields(decoded)
    algorithm = parts[0].encode("ascii")
    if not fields or fields[0] != algorithm:
        raise ConfigurationError("SSH public-key payload algorithm conflicts")
    if parts[0] == "ssh-ed25519" and (len(fields) != 2 or len(fields[1]) != 32):
        raise ConfigurationError("SSH Ed25519 public-key payload is invalid")
    if parts[0] == "ssh-rsa" and (len(fields) != 3 or not fields[1] or not fields[2]):
        raise ConfigurationError("SSH RSA public-key payload is invalid")
    if parts[0].startswith("ecdsa-") and (
        len(fields) != 3
        or fields[1] != parts[0].removeprefix("ecdsa-sha2-").encode("ascii")
        or not fields[2]
    ):
        raise ConfigurationError("SSH ECDSA public-key payload is invalid")
    if parts[0] == "sk-ssh-ed25519@openssh.com" and (
        len(fields) != 3 or len(fields[1]) != 32 or not fields[2]
    ):
        raise ConfigurationError("SSH security-key Ed25519 payload is invalid")
    if parts[0] == "sk-ecdsa-sha2-nistp256@openssh.com" and (
        len(fields) != 4 or fields[1] != b"nistp256" or not fields[2] or not fields[3]
    ):
        raise ConfigurationError("SSH security-key ECDSA payload is invalid")
    if len(parts) == 3 and (
        not parts[2] or any(ord(character) < 0x20 for character in parts[2])
    ):
        raise ConfigurationError("SSH public-key comment is invalid")
    return line


def _wire_fields(value: bytes) -> tuple[bytes, ...]:
    fields: list[bytes] = []
    offset = 0
    while offset < len(value):
        if len(value) - offset < 4:
            raise ConfigurationError("SSH public-key wire payload is truncated")
        length = int.from_bytes(value[offset : offset + 4], "big")
        offset += 4
        if length < 1 or length > len(value) - offset:
            raise ConfigurationError("SSH public-key wire field is invalid")
        fields.append(value[offset : offset + length])
        offset += length
    return tuple(fields)
