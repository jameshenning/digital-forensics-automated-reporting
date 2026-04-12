"""
DFARS Desktop - User configuration management.

Loads and saves %APPDATA%\\DFARS\\config.json with atomic writes.
Holds application-level settings that must persist across launches:
the Flask session secret, LLM provider config (Phase 4), update channel
(Phase 6), and so on.

The file is NOT where user credentials live — see auth.py for those.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any, Dict

from .paths import config_path, ensure_data_tree


# Defaults merged with whatever is on disk. Keys added here in future
# phases are automatically available to existing installs.
DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "session_secret": None,          # generated on first run
    # Networking — Agent Zero discovery
    "bind_host": "127.0.0.1",        # change to "0.0.0.0" to enable external integrations (Agent Zero in Docker)
    "preferred_port": 5099,          # try this first; fall back to random if taken
    "actual_port": None,             # written by main.py at every launch
    # Phase 4: Agent Zero integration
    # Default points at loopback because DFARS Desktop runs ON the host, not
    # inside the Docker container. host.docker.internal is a Docker-only DNS
    # name and won't resolve from the host side.
    "agent_zero_url": "http://127.0.0.1:5080",
    "agent_zero_api_key_encrypted": None,  # Fernet-encrypted via app.crypto
    # Phase 6: auto-updates
    "update_url": None,              # set to your manifest.json URL after first release
    "update_channel": "stable",
    "last_update_check": None,
}


def load() -> Dict[str, Any]:
    """Load config from disk, merged with defaults. Never raises."""
    path = config_path()
    if not path.exists():
        return dict(DEFAULT_CONFIG)

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return dict(DEFAULT_CONFIG)
    except (json.JSONDecodeError, OSError):
        # Corrupt config: fall back to defaults so the app still boots.
        # The caller can choose to re-save to heal the file.
        return dict(DEFAULT_CONFIG)

    merged = dict(DEFAULT_CONFIG)
    merged.update(data)
    return merged


def save(config: Dict[str, Any]) -> None:
    """
    Save config atomically.

    Writes to a tempfile in the same directory, fsyncs, and renames.
    This prevents a crashed write from leaving a truncated config
    that would brick the next launch.
    """
    ensure_data_tree()
    path = config_path()

    # Write to temp file in the same directory as the target so the
    # rename is atomic (same filesystem).
    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=".config_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        # Atomic replace
        os.replace(tmp_path, path)
    except Exception:
        # Clean up the tempfile if something went wrong before the rename
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def get_or_create_session_secret() -> str:
    """
    Return the persistent Flask session secret, generating one on first run.

    A persistent secret is required so login sessions survive application
    restarts. The secret is 32 cryptographically random bytes, hex-encoded.
    """
    config = load()
    if not config.get("session_secret"):
        config["session_secret"] = secrets.token_hex(32)
        save(config)
    return config["session_secret"]


def update(**kwargs: Any) -> Dict[str, Any]:
    """
    Merge `kwargs` into the stored config and save. Returns the new config.
    Unknown keys are accepted — forward-compat for future phases.
    """
    config = load()
    config.update(kwargs)
    save(config)
    return config
