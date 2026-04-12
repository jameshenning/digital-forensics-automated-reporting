"""
DFARS Desktop auto-update module.

The release flow:
    1. Developer builds + signs a release on their machine. The output is:
       - DFARS-Desktop-Setup-X.Y.Z.exe         (Inno Setup installer)
       - manifest.json                          (signed metadata)
    2. Both files get uploaded to a stable HTTPS URL.
    3. DFARS Desktop fetches manifest.json on demand (or on a schedule),
       verifies the signature against the embedded Ed25519 public key,
       compares versions, and (if newer) downloads the installer.
    4. The installer .sha256 is also verified before launch.
    5. DFARS launches the installer and exits — Inno Setup handles the
       actual file replacement (UAC prompt, file locking, restart of
       the new version).

Why this design:
    - The embedded public key means a compromised update server can't
      push a malicious update — the attacker would need the private
      key, which lives offline on the developer machine.
    - Reusing the existing Inno Setup installer for the actual file
      swap means we don't have to write a custom Windows file-replace
      mechanism (which is hard because the running .exe holds locks).
    - Signature verification happens BEFORE launching the installer,
      not after. A bad signature means we never even download the file.

This module is intentionally stdlib + cryptography only. No requests,
no httpx, no async — just urllib + json + the Ed25519 primitive from
`cryptography.hazmat.primitives.asymmetric.ed25519`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import __version__, config as app_config
from .update_key import PUBLIC_KEY_PEM, is_placeholder

log = logging.getLogger(__name__)


# ─── Tunables ──────────────────────────────────────────────

# Default update URL — overridable via config.json["update_url"]. The
# placeholder forces a fresh install to either configure a real URL or
# stay un-updated. Combined with the placeholder public key, this means
# a brand-new install will not phone home until the developer wires it up.
DEFAULT_UPDATE_URL = "https://example.com/dfars-desktop/manifest.json"

# How long manifest fetches can take before we give up
MANIFEST_TIMEOUT_SEC = 15.0

# How long the installer download is allowed to take
DOWNLOAD_TIMEOUT_SEC = 600.0


# ─── Errors ────────────────────────────────────────────────


class UpdateError(Exception):
    """Base class for updater problems shown to the user."""


class UpdateDisabled(UpdateError):
    """Updates are disabled (placeholder key, no URL, etc.)."""


class UpdateUnavailable(UpdateError):
    """Could not reach the update server."""


class UpdateBadSignature(UpdateError):
    """Manifest signature verification failed — possible tampering."""


class UpdateBadHash(UpdateError):
    """Downloaded installer's sha256 didn't match the manifest."""


# ─── Public types ──────────────────────────────────────────


@dataclass
class UpdateInfo:
    """Result of check_for_update()."""
    version: str
    notes: str
    released_at: str
    download_url: str
    sha256: str
    size_bytes: int
    is_newer: bool


# ─── Version comparison ───────────────────────────────────


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[.-](.+))?$")


def parse_version(v: str) -> tuple[int, int, int, str]:
    """
    Parse 'X.Y.Z' or 'X.Y.Z-suffix' into a comparable tuple.
    Suffix-less versions sort AFTER suffixed ones (1.0.0 > 1.0.0-rc1).
    """
    m = _VERSION_RE.match(v.strip())
    if not m:
        raise ValueError(f"Unparseable version string: {v!r}")
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    suffix = m.group(4) or ""
    return (major, minor, patch, suffix)


def is_newer(candidate: str, current: str) -> bool:
    """True if `candidate` is strictly newer than `current`."""
    c = parse_version(candidate)
    cur = parse_version(current)
    if c[:3] != cur[:3]:
        return c[:3] > cur[:3]
    # Same X.Y.Z — a release version (no suffix) beats any pre-release
    if c[3] == "" and cur[3] != "":
        return True
    if c[3] != "" and cur[3] == "":
        return False
    # Both have suffixes (or both don't): lexicographic
    return c[3] > cur[3]


# ─── Manifest signing format ──────────────────────────────


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """
    Serialize a manifest dict deterministically for signing/verification.
    Both signer and verifier MUST use this exact function so the bytes
    match. Never include the 'signature' field in the serialization.
    """
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_manifest_signature(manifest: dict) -> None:
    """
    Verify the Ed25519 signature on a manifest dict using the embedded
    public key. Raises UpdateBadSignature on any failure (missing
    signature, malformed key, bad signature bytes, etc.).
    """
    if is_placeholder():
        raise UpdateDisabled(
            "Update verification is not configured — the embedded public key "
            "is still the placeholder. See app/update_key.py for setup steps."
        )

    sig_b64 = manifest.get("signature")
    if not sig_b64 or not isinstance(sig_b64, str):
        raise UpdateBadSignature("Manifest is missing the 'signature' field.")

    try:
        import base64
        signature = base64.b64decode(sig_b64.encode("ascii"))
    except Exception:
        raise UpdateBadSignature("Manifest 'signature' is not valid base64.")

    try:
        key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode("ascii"))
    except Exception as e:
        raise UpdateBadSignature(f"Embedded public key could not be loaded: {e}")

    if not isinstance(key, Ed25519PublicKey):
        raise UpdateBadSignature(
            f"Embedded public key is not Ed25519 (got {type(key).__name__})."
        )

    payload = canonical_manifest_bytes(manifest)
    try:
        key.verify(signature, payload)
    except InvalidSignature:
        raise UpdateBadSignature(
            "Manifest signature did not verify against the embedded public key. "
            "This could mean the manifest was tampered with, or that the build "
            "machine is using a different signing key than the one embedded here."
        )


# ─── Public API ────────────────────────────────────────────


def get_update_url() -> str:
    cfg = app_config.load()
    return (cfg.get("update_url") or DEFAULT_UPDATE_URL).strip()


def check_for_update() -> UpdateInfo:
    """
    Fetch the manifest, verify its signature, and return parsed info.
    Always returns a populated UpdateInfo (with `is_newer` set) — the
    caller decides whether to act on it. Raises UpdateError on failure.
    """
    if is_placeholder():
        raise UpdateDisabled(
            "Updates are disabled until the embedded public key is replaced. "
            "See app/update_key.py for setup."
        )

    url = get_update_url()
    if not url or "example.com" in url:
        raise UpdateDisabled(
            "Update URL is not configured. Set 'update_url' in config.json."
        )

    log.info("Fetching update manifest from %s", url)
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"DFARS-Desktop/{__version__}",
            },
        )
        with urllib.request.urlopen(req, timeout=MANIFEST_TIMEOUT_SEC) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise UpdateUnavailable(f"Update server returned HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise UpdateUnavailable(f"Could not reach update server: {e.reason}")

    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise UpdateError(f"Update manifest is not valid JSON: {e}")

    if not isinstance(manifest, dict):
        raise UpdateError("Update manifest is not a JSON object.")

    # Verify signature BEFORE trusting any field
    verify_manifest_signature(manifest)

    # Extract Windows release info. The manifest layout is documented in
    # packaging/sign_release.py.
    try:
        version = str(manifest["version"]).strip()
        notes = str(manifest.get("notes", "")).strip()
        released_at = str(manifest.get("released_at", "")).strip()
        win = manifest["windows_x64"]
        download_url = str(win["url"]).strip()
        sha256 = str(win["sha256"]).strip().lower()
        size_bytes = int(win.get("size_bytes", 0))
    except (KeyError, ValueError, TypeError) as e:
        raise UpdateError(f"Manifest is missing required fields: {e}")

    if not version or not download_url or not sha256:
        raise UpdateError("Manifest version/url/sha256 are empty.")

    # Persist last-check timestamp regardless of result
    app_config.update(last_update_check=datetime.now().isoformat(timespec="seconds"))

    return UpdateInfo(
        version=version,
        notes=notes,
        released_at=released_at,
        download_url=download_url,
        sha256=sha256,
        size_bytes=size_bytes,
        is_newer=is_newer(version, __version__),
    )


def download_update(
    info: UpdateInfo,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Path:
    """
    Download the installer .exe to a temp file, verify its sha256, and
    return the path. Caller is responsible for cleanup if they choose
    not to launch it.
    """
    if not info.download_url:
        raise UpdateError("UpdateInfo has no download URL.")

    tmp = Path(tempfile.gettempdir()) / f"dfars-update-{info.version}.exe"
    log.info("Downloading %s -> %s", info.download_url, tmp)

    sha = hashlib.sha256()
    written = 0
    try:
        req = urllib.request.Request(
            info.download_url,
            headers={"User-Agent": f"DFARS-Desktop/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SEC) as resp:
            content_length = int(resp.headers.get("Content-Length", "0") or 0)
            total = info.size_bytes or content_length
            with open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    sha.update(chunk)
                    written += len(chunk)
                    if progress and total:
                        progress(written, total)
    except (urllib.error.URLError, OSError) as e:
        raise UpdateUnavailable(f"Failed to download installer: {e}")

    actual = sha.hexdigest().lower()
    if actual != info.sha256:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise UpdateBadHash(
            f"Downloaded installer hash mismatch.\n"
            f"  expected: {info.sha256}\n"
            f"  actual:   {actual}\n"
            f"This usually means the manifest is stale or the download was "
            f"corrupted. Try again; if it keeps happening, the manifest may "
            f"be inconsistent with the published installer."
        )

    return tmp


def apply_update(installer_path: Path) -> None:
    """
    Launch the installer and exit DFARS Desktop.

    The installer is the same Inno Setup .exe that fresh installs use,
    so it knows how to handle UAC, file locking, shortcut updates, and
    relaunching the new version. We just need to start it and get out
    of the way.
    """
    if not installer_path.exists():
        raise UpdateError(f"Installer not found at {installer_path}")

    log.info("Launching installer %s and exiting DFARS", installer_path)

    # Detach the installer process so we can exit without taking it down
    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )

    subprocess.Popen(
        [str(installer_path), "/SILENT", "/SUPPRESSMSGBOXES"],
        close_fds=True,
        creationflags=creationflags,
        # Don't pass stdin/stdout/stderr — let the installer take over
    )

    # Hand control back to the caller; the route handler should respond
    # to the user and then call sys.exit. We don't sys.exit here so the
    # current HTTP request can finish cleanly first.
