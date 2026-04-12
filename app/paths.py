"""
AppData directory discovery for DFARS Desktop.

Centralizes all filesystem paths so no other module has to hardcode
Windows-specific locations. First call to `ensure_data_tree()` creates
the directory layout under %APPDATA%\\DFARS\\ (or the platform equivalent
on macOS/Linux via platformdirs).
"""

from __future__ import annotations

from pathlib import Path

from platformdirs import user_data_dir, user_log_dir

APP_NAME = "DFARS"
# appauthor=False suppresses the vendor-subdirectory layer on Windows, so
# data lives at %APPDATA%\DFARS\ rather than %APPDATA%\DFARS\DFARS\.


def data_dir() -> Path:
    """Root user data directory. Windows: %APPDATA%\\DFARS"""
    return Path(user_data_dir(APP_NAME, appauthor=False, roaming=True))


def logs_dir() -> Path:
    """Application logs directory. Windows: %LOCALAPPDATA%\\DFARS\\Logs"""
    return Path(user_log_dir(APP_NAME, appauthor=False))


def db_path() -> Path:
    """Path to the forensics SQLite database."""
    return data_dir() / "forensics.db"


def auth_db_path() -> Path:
    """Path to the authentication SQLite database.

    Kept separate from forensics.db so exporting forensic data
    can't accidentally leak user credentials or MFA secrets.
    """
    return data_dir() / "auth.db"


def reports_dir() -> Path:
    """Directory where generated reports are written."""
    return data_dir() / "reports"


def _safe_path_segment(value: str) -> str:
    """Sanitize a string so it can't escape its parent directory."""
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in value)
    return cleaned.strip("._") or "unknown"


def evidence_files_root() -> Path:
    """Fallback root directory for evidence files (on system drive).
    Used only when no external evidence drive is configured for a case.
    """
    return data_dir() / "evidence_files"


def evidence_files_dir(
    case_id: str,
    evidence_id: str,
    evidence_drive_path: str = "",
) -> Path:
    """
    Where uploaded files for a particular evidence item are stored on disk.

    If *evidence_drive_path* is set, files go to
    ``<drive>/DFARS_Evidence/<case_id>/<evidence_id>/``.
    Otherwise falls back to ``%APPDATA%\\DFARS\\evidence_files\\``.

    Path components are sanitized so user-supplied IDs cannot traverse
    outside the intended directory.
    """
    if evidence_drive_path:
        return (
            Path(evidence_drive_path)
            / "DFARS_Evidence"
            / _safe_path_segment(case_id)
            / _safe_path_segment(evidence_id)
        )
    return (
        evidence_files_root()
        / _safe_path_segment(case_id)
        / _safe_path_segment(evidence_id)
    )


def audit_dir() -> Path:
    """Protected directory for audit trail logs."""
    return data_dir() / "admin" / "audit"


def case_audit_path(case_id: str) -> Path:
    """Audit log for a specific case."""
    return audit_dir() / "cases" / f"{_safe_path_segment(case_id)}_audit.txt"


def auth_audit_path() -> Path:
    """Global authentication / session audit log."""
    return audit_dir() / "auth_audit.txt"


def config_path() -> Path:
    """Path to the user preferences JSON (LLM provider, UI, etc.)."""
    return data_dir() / "config.json"


def schema_path() -> Path:
    """Path to the bundled forensics SQL schema file (inside the app package)."""
    return Path(__file__).parent / "schema" / "database_schema.sql"


def auth_schema_path() -> Path:
    """Path to the bundled auth SQL schema file (inside the app package)."""
    return Path(__file__).parent / "schema" / "auth_schema.sql"


def static_dir() -> Path:
    return Path(__file__).parent / "static"


def templates_dir() -> Path:
    return Path(__file__).parent / "templates"


def ensure_data_tree() -> dict[str, Path]:
    """
    Create the user data directory tree if it doesn't exist.
    Idempotent — safe to call on every launch.

    Returns a dict of the resolved paths for logging / debugging.
    """
    paths = {
        "data_dir": data_dir(),
        "logs_dir": logs_dir(),
        "reports_dir": reports_dir(),
        "audit_dir": audit_dir(),
        "audit_cases_dir": audit_dir() / "cases",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths
