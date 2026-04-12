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
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths
