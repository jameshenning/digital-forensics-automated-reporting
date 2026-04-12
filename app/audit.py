"""
DFARS Desktop - Tamper-resistant audit trail logging.

Every user action — page view, record creation, edit, login, logout —
is appended to a plain-text audit log stored under:

    %APPDATA%\\DFARS\\admin\\audit\\
        auth_audit.txt              ← logins, logouts, password changes, token ops
        cases\\
            <case_id>_audit.txt     ← per-case activity (evidence, custody, etc.)

Protection model (Windows):
    - The admin\\audit\\ directory is marked Hidden + System.
    - Each .txt file is marked Read-Only after creation.
    - The write helper temporarily clears Read-Only, appends, then
      restores it. This prevents casual editing but not a determined
      admin — true tamper-proofing would need cryptographic chaining,
      which can be added later.

Log line format (pipe-delimited, one per action):
    YYYY-MM-DDTHH:MM:SS.ffffff | username | ACTION_CODE | detail text
"""

from __future__ import annotations

import ctypes
import logging
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Optional

from .paths import audit_dir, auth_audit_path, case_audit_path, ensure_data_tree

log = logging.getLogger(__name__)

# Windows file attribute constants
_FILE_ATTRIBUTE_READONLY = 0x01
_FILE_ATTRIBUTE_HIDDEN = 0x02
_FILE_ATTRIBUTE_SYSTEM = 0x04


# ── Low-level helpers ────────────────────────────────────────


def _protect_dir(path: Path) -> None:
    """Mark a directory as Hidden + System on Windows."""
    if os.name != "nt":
        return
    try:
        current = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
        if current == -1:
            return
        ctypes.windll.kernel32.SetFileAttributesW(  # type: ignore[attr-defined]
            str(path),
            current | _FILE_ATTRIBUTE_HIDDEN | _FILE_ATTRIBUTE_SYSTEM,
        )
    except Exception as e:
        log.debug("Could not set directory attributes on %s: %s", path, e)


def _set_readonly(path: Path) -> None:
    """Set a file to Read-Only on Windows (+ cross-platform fallback)."""
    if os.name == "nt":
        try:
            current = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
            if current == -1:
                return
            ctypes.windll.kernel32.SetFileAttributesW(  # type: ignore[attr-defined]
                str(path),
                current | _FILE_ATTRIBUTE_READONLY,
            )
        except Exception:
            pass
    else:
        try:
            path.chmod(path.stat().st_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
        except Exception:
            pass


def _clear_readonly(path: Path) -> None:
    """Temporarily remove Read-Only so the file can be appended to."""
    if os.name == "nt":
        try:
            current = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
            if current == -1:
                return
            ctypes.windll.kernel32.SetFileAttributesW(  # type: ignore[attr-defined]
                str(path),
                current & ~_FILE_ATTRIBUTE_READONLY,
            )
        except Exception:
            pass
    else:
        try:
            path.chmod(path.stat().st_mode | stat.S_IWUSR)
        except Exception:
            pass


def _append_line(path: Path, line: str) -> None:
    """
    Append a single line to an audit file, handling protection.

    Creates parent dirs and the file header on first write.
    """
    first_write = not path.exists()

    # Ensure directory tree exists
    path.parent.mkdir(parents=True, exist_ok=True)

    if not first_write:
        _clear_readonly(path)

    try:
        with open(path, "a", encoding="utf-8") as f:
            if first_write:
                f.write(_file_header(path.stem))
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        log.error("Audit write failed for %s: %s", path, e)
    finally:
        _set_readonly(path)

    if first_write:
        # Protect the parent audit directory
        _protect_dir(audit_dir())
        _protect_dir(audit_dir() / "cases")


def _file_header(name: str) -> str:
    """Header written once when a new audit file is created."""
    ts = datetime.now().isoformat()
    return (
        f"{'=' * 80}\n"
        f"  DFARS DESKTOP AUDIT LOG — {name}\n"
        f"  Created: {ts}\n"
        f"  WARNING: This file is protected. Do not modify or delete.\n"
        f"  Format: TIMESTAMP | USER | ACTION | DETAILS\n"
        f"{'=' * 80}\n\n"
    )


def _format(user: str, action: str, details: str) -> str:
    """Build a single audit line."""
    ts = datetime.now().isoformat(timespec="microseconds")
    safe_user = user or "SYSTEM"
    return f"{ts} | {safe_user} | {action} | {details}"


# ── Public API ───────────────────────────────────────────────


def log_case(
    case_id: str,
    user: str,
    action: str,
    details: str,
) -> None:
    """
    Append an entry to a case-specific audit log.

    Called for every action within a case: viewing, adding evidence,
    custody events, hash verifications, tool logs, analysis notes,
    file uploads, AI operations, report generation, edits, etc.
    """
    path = case_audit_path(case_id)
    line = _format(user, action, details)
    _append_line(path, line)


def log_auth(
    user: str,
    action: str,
    details: str,
) -> None:
    """
    Append an entry to the global authentication audit log.

    Called for logins, logouts, failed attempts, password changes,
    MFA setup, API token operations, and non-case system actions.
    """
    path = auth_audit_path()
    line = _format(user, action, details)
    _append_line(path, line)


# ── Action code constants ────────────────────────────────────
# Use these as the `action` parameter for consistency across
# all call sites. Grep-friendly, all-caps, underscore-separated.

# Auth actions
LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILED = "LOGIN_FAILED"
LOGOUT = "LOGOUT"
PASSWORD_CHANGED = "PASSWORD_CHANGED"
MFA_ENABLED = "MFA_ENABLED"
MFA_RECOVERY_USED = "MFA_RECOVERY_USED"
MFA_VERIFIED = "MFA_VERIFIED"
API_TOKEN_CREATED = "API_TOKEN_CREATED"
API_TOKEN_REVOKED = "API_TOKEN_REVOKED"
SETUP_ACCOUNT = "SETUP_ACCOUNT"
SESSION_EXPIRED = "SESSION_EXPIRED"

# Case-level actions
CASE_CREATED = "CASE_CREATED"
CASE_VIEWED = "CASE_VIEWED"
CASE_EDITED = "CASE_EDITED"
EVIDENCE_ADDED = "EVIDENCE_ADDED"
EVIDENCE_DELETED = "EVIDENCE_DELETED"
CUSTODY_ADDED = "CUSTODY_ADDED"
CUSTODY_EDITED = "CUSTODY_EDITED"
CUSTODY_DELETED = "CUSTODY_DELETED"
HASH_ADDED = "HASH_ADDED"
TOOL_LOGGED = "TOOL_LOGGED"
ANALYSIS_ADDED = "ANALYSIS_ADDED"
FILE_UPLOADED = "FILE_UPLOADED"
FILE_DELETED = "FILE_DELETED"
AI_ENHANCE = "AI_ENHANCE"
AI_CLASSIFY = "AI_CLASSIFY"
AI_SUMMARIZE = "AI_SUMMARIZE"
AI_ANALYZE_EVIDENCE = "AI_ANALYZE_EVIDENCE"
FORENSIC_ANALYZE = "FORENSIC_ANALYZE"
REPORT_PREVIEWED = "REPORT_PREVIEWED"
RECORD_SHARED = "RECORD_SHARED"
RECORD_PRINTED = "RECORD_PRINTED"
REPORT_DOWNLOADED = "REPORT_DOWNLOADED"
REPORT_GENERATED_API = "REPORT_GENERATED_API"
LINK_ANALYSIS_VIEWED = "LINK_ANALYSIS_VIEWED"
ENTITY_ADDED = "ENTITY_ADDED"
ENTITY_EDITED = "ENTITY_EDITED"
ENTITY_DELETED = "ENTITY_DELETED"
LINK_ADDED = "LINK_ADDED"
LINK_DELETED = "LINK_DELETED"
EVENT_ADDED = "EVENT_ADDED"
EVENT_EDITED = "EVENT_EDITED"
EVENT_DELETED = "EVENT_DELETED"

# System / non-case actions
DASHBOARD_VIEWED = "DASHBOARD_VIEWED"
SETTINGS_CHANGED = "SETTINGS_CHANGED"
DRIVE_LISTED = "DRIVE_LISTED"

# API actions (external integrations)
API_CASE_CREATED = "API_CASE_CREATED"
API_CASE_VIEWED = "API_CASE_VIEWED"
API_CASE_UPDATED = "API_CASE_UPDATED"
API_EVIDENCE_ADDED = "API_EVIDENCE_ADDED"
API_CUSTODY_ADDED = "API_CUSTODY_ADDED"
API_HASH_ADDED = "API_HASH_ADDED"
API_TOOL_LOGGED = "API_TOOL_LOGGED"
API_ANALYSIS_ADDED = "API_ANALYSIS_ADDED"
API_REPORT_GENERATED = "API_REPORT_GENERATED"
API_TOKEN_VERIFIED = "API_TOKEN_VERIFIED"
