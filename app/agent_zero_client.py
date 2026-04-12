"""
DFARS Desktop → Agent Zero client.

Used by the internal AI helper endpoints (/api/internal/ai/*) when the
DFARS UI wants to invoke Agent Zero's LLM for description enhancement,
classification, or summary generation.

Talks to the _dfars_integration plugin's API endpoints inside Agent Zero
using the X-API-KEY header (which maps to Agent Zero's mcp_server_token
on the other side). This avoids the session-cookie/CSRF dance entirely.

The Agent Zero base URL and API key are stored in DFARS config.json,
with the key encrypted at rest via app.crypto (Fernet via keyring).
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Optional

from . import config as app_config, crypto

log = logging.getLogger(__name__)


class AgentZeroError(Exception):
    """Raised on any failure talking to Agent Zero."""


def _load_settings() -> tuple[str, Optional[str]]:
    """Return (base_url, decrypted_api_key) from config. Key may be None."""
    cfg = app_config.load()
    url = (cfg.get("agent_zero_url") or "").rstrip("/")
    key_enc = cfg.get("agent_zero_api_key_encrypted")
    key: Optional[str] = None
    if key_enc:
        try:
            key = crypto.decrypt(key_enc).decode("utf-8")
        except Exception as e:
            log.warning("Failed to decrypt Agent Zero API key: %s", e)
            key = None
    return url, key


def save_settings(url: str, api_key: Optional[str]) -> None:
    """
    Persist the Agent Zero connection. If api_key is empty, the existing
    encrypted key is left alone — this lets the user update the URL
    without re-entering the key.
    """
    updates: dict[str, Any] = {"agent_zero_url": url.strip().rstrip("/")}
    if api_key:
        updates["agent_zero_api_key_encrypted"] = crypto.encrypt(api_key.strip())
    app_config.update(**updates)


def clear_api_key() -> None:
    """Wipe the stored Agent Zero API key."""
    app_config.update(agent_zero_api_key_encrypted=None)


def is_configured() -> bool:
    url, key = _load_settings()
    return bool(url and key)


def _post(path: str, body: dict, timeout: float = 60.0) -> dict:
    url, key = _load_settings()
    if not url:
        raise AgentZeroError("Agent Zero URL is not configured.")
    if not key:
        raise AgentZeroError("Agent Zero API key is not configured.")

    full_url = url + path
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        full_url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": key,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        if e.code == 401:
            raise AgentZeroError(
                "Agent Zero rejected the API key (401). "
                "Verify mcp_server_token in Agent Zero settings matches what's stored here."
            )
        raise AgentZeroError(
            f"Agent Zero returned HTTP {e.code}: {body_text[:300]}"
        )
    except urllib.error.URLError as e:
        raise AgentZeroError(
            f"Could not reach Agent Zero at {url}: {e.reason}. "
            f"Is the agent-zero container running and reachable?"
        )


# Agent Zero's API dispatcher routes plugin endpoints at:
#   /api/plugins/<plugin_name>/<handler_filename_without_py>
# So our endpoints live at /api/plugins/_dfars_integration/dfars_<verb>
_PLUGIN = "/api/plugins/_dfars_integration"


def test_connection() -> tuple[bool, str]:
    """
    Ping the dfars_enhance endpoint with trivial input. Returns (ok, message).
    Used by the 'Test Connection' button in DFARS settings.
    """
    if not is_configured():
        return False, "URL or API key not configured."
    try:
        result = _post(f"{_PLUGIN}/dfars_enhance", {"text": "Test connection"})
    except AgentZeroError as e:
        return False, str(e)
    if "error" in result:
        return False, str(result["error"])
    if "enhanced" in result:
        return True, "Connection OK."
    return False, f"Unexpected response shape: {list(result.keys())}"


def enhance_description(text: str) -> str:
    """Ask Agent Zero to enhance a case description."""
    result = _post(f"{_PLUGIN}/dfars_enhance", {"text": text})
    if "error" in result:
        raise AgentZeroError(str(result["error"]))
    return result.get("enhanced", "")


def classify_case(text: str) -> dict:
    """Ask Agent Zero to classify a case description."""
    result = _post(f"{_PLUGIN}/dfars_classify", {"text": text})
    if "error" in result:
        raise AgentZeroError(str(result["error"]))
    return result


def summarize_case(case_payload: dict) -> dict:
    """Ask Agent Zero to generate executive summary + conclusion."""
    result = _post(f"{_PLUGIN}/dfars_summarize", case_payload, timeout=120.0)
    if "error" in result:
        raise AgentZeroError(str(result["error"]))
    return result


def analyze_evidence(payload: dict) -> dict:
    """
    Send a single evidence item's file metadata + investigator OSINT
    narrative to Agent Zero for forensic synthesis. Returns
    {report_markdown, tools_used, platforms_used} or raises
    AgentZeroError on failure.
    """
    result = _post(f"{_PLUGIN}/dfars_analyze_evidence", payload, timeout=180.0)
    if "error" in result:
        raise AgentZeroError(str(result["error"]))
    return result


def forensic_analyze(payload: dict) -> dict:
    """
    Deep forensic analysis — Agent Zero downloads evidence files,
    runs Kali Linux / forensic tools against them, parses the output,
    and returns structured findings + an investigative narrative.

    Payload must include dfars_api_url and dfars_api_token so Agent Zero
    can download the actual files from DFARS Desktop.

    Returns {status, tools_run, findings, report_markdown} or raises.
    Timeout is 5 minutes because tool execution takes time.
    """
    result = _post(f"{_PLUGIN}/dfars_forensic_analyze", payload, timeout=300.0)
    if result.get("error") and result.get("status") != "partial":
        raise AgentZeroError(str(result["error"]))
    return result
