"""
DFARS Desktop - API token management.

Bearer tokens for /api/v1/* are stored as Argon2id hashes in auth.db
(same approach as the user password and recovery codes). The plaintext
is shown to the user exactly once at generation time and never again.

Token format: "dfars_" + 32 url-safe base64 bytes (~50 chars total).
The "dfars_" prefix makes accidental leaks (in pasted snippets, logs,
GitHub commits) trivially identifiable.
"""

from __future__ import annotations

import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator, List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .paths import auth_db_path


_TOKEN_PREFIX = "dfars_"
_TOKEN_BYTES = 32           # ~256 bits of entropy
_PREVIEW_LEN = 12           # how many chars of plaintext to keep for UI display

_hasher = PasswordHasher()


# ─── DB connection ─────────────────────────────────────────


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(auth_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


# ─── Token generation / verification ──────────────────────


def _generate_plaintext() -> str:
    return _TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)


def generate(user_id: int, name: str) -> tuple[int, str]:
    """
    Create a new API token for the given user.

    Returns (token_id, plaintext). The plaintext is the only time the
    raw token is ever visible — caller MUST display it to the user
    immediately and discard it.
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("Token name is required.")
    if len(name) > 100:
        raise ValueError("Token name is too long.")

    plaintext = _generate_plaintext()
    token_hash = _hasher.hash(plaintext)
    preview = plaintext[: _PREVIEW_LEN]

    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO api_tokens (user_id, name, token_hash, token_preview)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, name, token_hash, preview),
        )
        conn.commit()
        return int(cursor.lastrowid or 0), plaintext


def verify(plaintext: str) -> Optional[dict]:
    """
    Look up the token by trying every stored hash. Returns the token row
    (with the user joined in) on success, None otherwise. Updates
    last_used_at on success.

    Performance note: Argon2id verification is ~100ms per call. With a
    handful of tokens (the realistic case for a single-user desktop
    install), the cumulative cost of trying each is acceptable. If we
    ever support thousands of tokens, we'd want a faster identifier
    (e.g., HMAC fingerprint) to narrow the search first.
    """
    if not plaintext or not plaintext.startswith(_TOKEN_PREFIX):
        return None

    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT t.id, t.user_id, t.name, t.token_hash, t.token_preview,
                   t.created_at, t.last_used_at,
                   u.username
              FROM api_tokens t
              JOIN users u ON u.id = t.user_id
            """
        ).fetchall()

        for row in rows:
            try:
                _hasher.verify(row["token_hash"], plaintext)
            except (VerifyMismatchError, InvalidHashError):
                continue

            # Match — update last_used_at
            now = datetime.now().isoformat(timespec="seconds")
            conn.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            conn.commit()

            return dict(row) | {"last_used_at": now}

    return None


# ─── Listing / revocation ─────────────────────────────────


def list_for_user(user_id: int) -> List[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, name, token_preview, created_at, last_used_at
              FROM api_tokens
             WHERE user_id = ?
             ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def revoke(token_id: int, user_id: int) -> bool:
    """
    Delete a token by ID. The user_id check prevents cross-user revocation
    if we ever go multi-user. Returns True if a row was deleted.
    """
    with _connect() as conn:
        cursor = conn.execute(
            "DELETE FROM api_tokens WHERE id = ? AND user_id = ?",
            (token_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
