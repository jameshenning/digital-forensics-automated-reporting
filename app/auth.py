"""
DFARS Desktop - Authentication module.

Single-user authentication backed by auth.db. Responsibilities:
- Argon2id password hashing (argon2-cffi defaults: memory=64MB, time=3, parallelism=4)
- Password verification with automatic rehash on parameter change
- Failed-attempt rate limiting with lockout
- Constant-time behavior on unknown users (prevents username enumeration)
- TOTP (time-based) MFA with QR enrollment + one-time recovery codes (Phase 3)

This module does NOT handle:
- HTTP / sessions / cookies → see auth_routes.py
- Fernet key management for encrypting TOTP secrets → see crypto.py
"""

from __future__ import annotations

import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Iterator, List, Optional

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from . import crypto
from .paths import auth_db_path, auth_schema_path


# ─── Tunables ──────────────────────────────────────────────

MAX_FAILED_ATTEMPTS = 5        # before lockout kicks in
LOCKOUT_MINUTES = 5             # how long the lockout lasts
MIN_USERNAME_LENGTH = 3
MIN_PASSWORD_LENGTH = 10        # reasonable floor; MFA strongly recommended

# MFA / TOTP
TOTP_ISSUER = "DFARS Desktop"
TOTP_VALID_WINDOW = 1           # accept the previous and next 30-second window for clock drift
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_GROUP_LEN = 5     # 5 hex chars per group; format "xxxxx-xxxxx"

# Single shared Argon2 hasher. Defaults are reasonable for a desktop app
# (~100ms per hash on modern hardware).
_hasher = PasswordHasher()

# A constant hash used when the supplied username doesn't exist, so the
# verify call takes the same time whether or not the user is real. This
# prevents an attacker from learning valid usernames via timing.
_DUMMY_HASH = _hasher.hash("dfars-desktop-timing-guard")


# ─── Exceptions ────────────────────────────────────────────

class AuthError(Exception):
    """Base class for authentication errors that are safe to show the user."""


class InvalidCredentials(AuthError):
    """Username or password wrong — message kept vague to avoid enumeration."""


class AccountLocked(AuthError):
    """Too many failed attempts; locked out for a cooldown period."""
    def __init__(self, seconds_remaining: int):
        super().__init__(
            f"Account is locked. Try again in {seconds_remaining} seconds."
        )
        self.seconds_remaining = seconds_remaining


class ValidationError(AuthError):
    """Username or password failed validation rules."""


# ─── DB connection helpers ────────────────────────────────


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(
        auth_db_path(),
        detect_types=0,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create the auth.db schema if it doesn't exist. Idempotent."""
    sql_path = auth_schema_path()
    if not sql_path.exists():
        raise FileNotFoundError(f"Auth schema not found at {sql_path}")
    schema_sql = sql_path.read_text(encoding="utf-8")
    with _connect() as conn:
        conn.executescript(schema_sql)
        conn.commit()


# ─── Queries ──────────────────────────────────────────────


def user_exists() -> bool:
    """True if any user is registered. Used to gate the first-run setup flow."""
    with _connect() as conn:
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return int(row[0]) > 0


def get_user(username: str) -> Optional[dict]:
    """Return the user row as a dict, or None if not found."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None


# ─── Validation ───────────────────────────────────────────


def _validate_username(username: str) -> str:
    username = username.strip()
    if not username:
        raise ValidationError("Username is required.")
    if len(username) < MIN_USERNAME_LENGTH:
        raise ValidationError(
            f"Username must be at least {MIN_USERNAME_LENGTH} characters."
        )
    if len(username) > 64:
        raise ValidationError("Username is too long (max 64 characters).")
    # Allow alphanumerics, underscore, hyphen, dot. No spaces.
    if not all(c.isalnum() or c in "._-" for c in username):
        raise ValidationError(
            "Username may only contain letters, digits, '.', '_', or '-'."
        )
    return username


def _validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > 1024:
        # Argon2 accepts long strings, but we cap to avoid DoS via huge inputs.
        raise ValidationError("Password is too long.")


# ─── Mutations ────────────────────────────────────────────


def create_user(username: str, password: str) -> int:
    """
    Create the single application user. Raises ValidationError if inputs
    are invalid, or AuthError if a user already exists (single-user mode).
    Returns the new user's ID.
    """
    if user_exists():
        raise AuthError(
            "A user account already exists. Single-user mode is enforced."
        )

    username = _validate_username(username)
    _validate_password(password)

    password_hash = _hasher.hash(password)
    with _connect() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            conn.commit()
            return int(cursor.lastrowid or 0)
        except sqlite3.IntegrityError:
            # Shouldn't reach this with the user_exists() guard, but belt-and-suspenders
            raise AuthError(f"Username '{username}' is already in use.")


def verify_password(username: str, password: str) -> dict:
    """
    Verify the user's credentials. On success, returns the user row (dict)
    with updated last_login. On failure, raises one of:
    - AccountLocked  (too many failed attempts, in cooldown)
    - InvalidCredentials  (wrong username or password — vague on purpose)

    Automatically rehashes the password if Argon2 parameters have changed
    since the hash was created (e.g., after argon2-cffi bumps defaults).
    """
    user = get_user(username)

    # Constant-time guard against username enumeration: if the user doesn't
    # exist, verify against a dummy hash so the call takes roughly as long
    # as the real path. We still raise InvalidCredentials either way.
    if user is None:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        raise InvalidCredentials("Invalid username or password.")

    # Check active lockout before doing any crypto work
    locked_until_raw = user.get("locked_until")
    if locked_until_raw:
        try:
            locked_until = datetime.fromisoformat(locked_until_raw)
        except ValueError:
            locked_until = None
        if locked_until and locked_until > datetime.now():
            remaining = int((locked_until - datetime.now()).total_seconds())
            raise AccountLocked(max(remaining, 1))

    # Verify
    try:
        _hasher.verify(user["password_hash"], password)
    except (VerifyMismatchError, InvalidHashError):
        _record_failed_attempt(username, int(user.get("failed_login_count") or 0))
        raise InvalidCredentials("Invalid username or password.")

    # Success: reset counters, update last_login
    _record_successful_login(username)

    # Opportunistic rehash if parameters changed
    if _hasher.check_needs_rehash(user["password_hash"]):
        new_hash = _hasher.hash(password)
        with _connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user["id"]),
            )
            conn.commit()

    # Return the freshly-updated user row so callers get last_login etc.
    fresh = get_user(username)
    assert fresh is not None
    return fresh


def update_password(username: str, current_password: str, new_password: str) -> None:
    """
    Change the user's password. The current password must verify successfully
    first (which also enforces lockout). Raises ValidationError / AuthError.
    """
    verify_password(username, current_password)  # raises on failure
    _validate_password(new_password)
    new_hash = _hasher.hash(new_password)
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username),
        )
        conn.commit()


# ─── Internal helpers ─────────────────────────────────────


def _record_failed_attempt(username: str, current_count: int) -> None:
    new_count = current_count + 1
    locked_until: Optional[str] = None
    if new_count >= MAX_FAILED_ATTEMPTS:
        locked_until = (
            datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
        ).isoformat(timespec="seconds")

    with _connect() as conn:
        conn.execute(
            """
            UPDATE users
               SET failed_login_count = ?, locked_until = ?
             WHERE username = ?
            """,
            (new_count, locked_until, username),
        )
        conn.commit()


def _record_successful_login(username: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            """
            UPDATE users
               SET failed_login_count = 0,
                   locked_until = NULL,
                   last_login = ?
             WHERE username = ?
            """,
            (now, username),
        )
        conn.commit()


# ─── MFA: TOTP enrollment & verification ───────────────────


def is_mfa_enabled(username: str) -> bool:
    """True if the user has MFA fully enabled and a stored TOTP secret."""
    user = get_user(username)
    if not user:
        return False
    return bool(user.get("mfa_enabled")) and bool(user.get("totp_secret"))


def generate_totp_secret() -> str:
    """Generate a new base32 TOTP secret. Not stored — caller must persist."""
    return pyotp.random_base32()


def totp_provisioning_uri(username: str, secret: str) -> str:
    """
    Build the otpauth:// URI used by authenticator apps. The user scans
    this (via QR code) and the app starts emitting matching codes.
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=TOTP_ISSUER,
    )


def enable_mfa(username: str, secret: str) -> None:
    """
    Persist a verified TOTP secret. Call only after the user has proven
    they can read codes from their authenticator (i.e., one valid code
    was already verified against this secret in memory).
    """
    user = get_user(username)
    if not user:
        raise AuthError("User not found")

    # Encrypt the secret before persisting so a stolen auth.db isn't
    # enough to bypass MFA on its own.
    encrypted = crypto.encrypt(secret)
    now = datetime.now().isoformat(timespec="seconds")

    with _connect() as conn:
        conn.execute(
            """
            UPDATE users
               SET totp_secret = ?,
                   mfa_enabled = 1,
                   mfa_enrolled_at = ?
             WHERE username = ?
            """,
            (encrypted, now, username),
        )
        conn.commit()


def disable_mfa(username: str, current_password: str) -> None:
    """
    Turn off MFA. Requires re-entry of the password as a defense against
    attackers who somehow gained a logged-in session and want to weaken
    the account. Also revokes all outstanding recovery codes.
    """
    verify_password(username, current_password)  # raises on failure
    user = get_user(username)
    if not user:
        raise AuthError("User not found")

    with _connect() as conn:
        conn.execute(
            """
            UPDATE users
               SET totp_secret = NULL,
                   mfa_enabled = 0,
                   mfa_enrolled_at = NULL
             WHERE username = ?
            """,
            (username,),
        )
        conn.execute(
            "DELETE FROM recovery_codes WHERE user_id = ?",
            (user["id"],),
        )
        conn.commit()


def verify_totp(username: str, code: str) -> bool:
    """
    Verify a TOTP code. Returns True/False — does NOT raise on bad code,
    so callers control how to message the user. Returns False (without
    crashing) if the stored secret can't be decrypted, so the user can
    fall through to recovery codes.
    """
    user = get_user(username)
    if not user or not user.get("totp_secret"):
        return False

    secret_bytes = crypto.try_decrypt(user["totp_secret"])
    if secret_bytes is None:
        return False

    secret = secret_bytes.decode("ascii")
    totp = pyotp.TOTP(secret)
    # Strip whitespace and any spacing the user might have typed
    cleaned = "".join(ch for ch in code if ch.isdigit())
    if len(cleaned) != 6:
        return False
    return totp.verify(cleaned, valid_window=TOTP_VALID_WINDOW)


# ─── MFA: recovery codes ──────────────────────────────────


def _format_recovery_code() -> str:
    """Return a fresh xxxxx-xxxxx hex code (~50 bits of entropy)."""
    g1 = secrets.token_hex(RECOVERY_CODE_GROUP_LEN // 2 + 1)[:RECOVERY_CODE_GROUP_LEN]
    g2 = secrets.token_hex(RECOVERY_CODE_GROUP_LEN // 2 + 1)[:RECOVERY_CODE_GROUP_LEN]
    return f"{g1}-{g2}"


def _normalize_recovery_code(code: str) -> str:
    """Lowercase, strip whitespace, ensure exactly one hyphen."""
    cleaned = "".join(ch.lower() for ch in code if not ch.isspace())
    return cleaned


def generate_recovery_codes(username: str) -> List[str]:
    """
    Generate, hash, and persist a fresh batch of recovery codes for the
    user. Returns the plaintext codes — these are the ONLY time they'll
    ever be visible. Any existing unused codes for this user are revoked.
    """
    user = get_user(username)
    if not user:
        raise AuthError("User not found")

    codes = [_format_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    hashes = [_hasher.hash(_normalize_recovery_code(c)) for c in codes]

    with _connect() as conn:
        # Revoke any prior codes
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
        conn.executemany(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            [(user["id"], h) for h in hashes],
        )
        conn.commit()

    return codes


def remaining_recovery_codes(username: str) -> int:
    """Count how many unused recovery codes the user has."""
    user = get_user(username)
    if not user:
        return 0
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
            (user["id"],),
        ).fetchone()
        return int(row[0])


def verify_recovery_code(username: str, code: str) -> bool:
    """
    Verify a one-time recovery code. On success, marks the code used and
    returns True. Returns False otherwise. Like verify_totp, does NOT
    raise — callers decide messaging.
    """
    user = get_user(username)
    if not user:
        return False

    cleaned = _normalize_recovery_code(code)
    if not cleaned:
        return False

    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, code_hash FROM recovery_codes
            WHERE user_id = ? AND used_at IS NULL
            """,
            (user["id"],),
        ).fetchall()

        for row in rows:
            try:
                _hasher.verify(row["code_hash"], cleaned)
            except (VerifyMismatchError, InvalidHashError):
                continue

            # Match — mark as used and commit
            conn.execute(
                "UPDATE recovery_codes SET used_at = ? WHERE id = ?",
                (datetime.now().isoformat(timespec="seconds"), row["id"]),
            )
            conn.commit()
            return True

    return False
