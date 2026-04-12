"""
DFARS Desktop - encryption key management for secrets at rest.

Used by auth.py to encrypt the user's TOTP secret before writing it to
auth.db. Without encryption, anyone who copies auth.db gets the MFA
seed; with it, they also need the Fernet key.

Key storage (in order of preference):

1. Keyring (Windows Credential Manager via DPAPI, macOS Keychain, or
   Secret Service on Linux). This ties the key to the current OS user
   account — moving the data to another user or machine breaks decryption,
   which is exactly what we want for a forensic tool.

2. File fallback at %APPDATA%\\DFARS\\.keyfile if keyring is unavailable.
   This is strictly worse (the file sits next to auth.db) but ensures
   the app still works in containers, WSL, minimal environments, etc.
   The file is created with 0o600 permissions on POSIX; on Windows the
   ACLs come from inheritance and there's no portable way to restrict
   further from Python.

A lost key means encrypted TOTP secrets become unrecoverable, but the
user's **recovery codes** (stored as separate hashes in auth.db) still
work, so they can always log in and re-enroll MFA.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from .paths import data_dir, ensure_data_tree

log = logging.getLogger(__name__)

_KEYRING_SERVICE = "DFARS Desktop"
_KEYRING_USERNAME = "totp_encryption_key"
_KEYFILE_NAME = ".keyfile"


# ─── Key acquisition ───────────────────────────────────────


def _keyfile_path() -> Path:
    return data_dir() / _KEYFILE_NAME


def _try_keyring_get() -> Optional[str]:
    """Read the Fernet key from the OS keyring. Returns None on any failure."""
    try:
        import keyring
        value = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        return value
    except Exception as e:
        log.debug("Keyring get failed: %s", e)
        return None


def _try_keyring_set(key: str) -> bool:
    """Write the Fernet key to the OS keyring. Returns True on success."""
    try:
        import keyring
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, key)
        return True
    except Exception as e:
        log.debug("Keyring set failed: %s", e)
        return False


def _read_keyfile() -> Optional[str]:
    path = _keyfile_path()
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="ascii").strip()
    except OSError as e:
        log.warning("Failed to read keyfile: %s", e)
        return None


def _write_keyfile(key: str) -> None:
    ensure_data_tree()
    path = _keyfile_path()
    path.write_text(key, encoding="ascii")
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        # Windows doesn't honour chmod portably; ACLs come from parent dir.
        pass


def _get_or_create_key() -> bytes:
    """
    Return the Fernet key as bytes, creating one on first use.
    Tries keyring first, then falls back to a keyfile in AppData.
    """
    # 1. Try keyring
    key = _try_keyring_get()
    if key:
        return key.encode("ascii")

    # 2. Try keyfile fallback
    key = _read_keyfile()
    if key:
        log.info("Loaded crypto key from keyfile fallback")
        return key.encode("ascii")

    # 3. Generate a new key, prefer keyring for storage, fall back to file
    new_key = Fernet.generate_key().decode("ascii")
    if _try_keyring_set(new_key):
        log.info("Generated new crypto key, stored in OS keyring")
    else:
        _write_keyfile(new_key)
        log.warning(
            "Keyring unavailable; stored crypto key in %s. "
            "This is less secure than keyring — see docs.",
            _keyfile_path(),
        )
    return new_key.encode("ascii")


# ─── Public API ────────────────────────────────────────────


def encrypt(plaintext: bytes | str) -> str:
    """Encrypt and return a URL-safe base64 ciphertext string."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    f = Fernet(_get_or_create_key())
    return f.encrypt(plaintext).decode("ascii")


def decrypt(ciphertext: str) -> bytes:
    """
    Decrypt a Fernet ciphertext string. Raises InvalidToken if the key
    has been rotated/lost or the ciphertext was tampered with.
    """
    f = Fernet(_get_or_create_key())
    return f.decrypt(ciphertext.encode("ascii"))


def try_decrypt(ciphertext: str) -> Optional[bytes]:
    """
    Non-raising decrypt: returns None on InvalidToken. Used by MFA flows
    that should degrade to 'recovery codes only' if the key is missing.
    """
    try:
        return decrypt(ciphertext)
    except InvalidToken:
        log.warning(
            "Failed to decrypt stored ciphertext — key may have been "
            "rotated or lost. User must re-enroll MFA."
        )
        return None
