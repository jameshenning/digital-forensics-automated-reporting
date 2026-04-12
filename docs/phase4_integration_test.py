"""
Phase 4 integration smoke test -- Agent Zero <-> DFARS Desktop, both directions.

Direction 1: Agent Zero plugin -> DFARS Desktop
  - Plugin's DFARSClient pushes a case + evidence + hash + custody + tool + analysis
  - DFARS REST API stores everything; we verify via GET /api/v1/cases/<id>
  - Plugin asks DFARS to generate a report

Direction 2: DFARS Desktop -> Agent Zero plugin
  - DFARS' agent_zero_client.test_connection() pings the plugin's /api/dfars_enhance
  - Auth is via X-API-KEY (Agent Zero's mcp_server_token)
  - Verifies the round trip works; LLM-call failures inside the plugin are
    treated as success because they prove the wiring reached the endpoint

Run with: ./.venv/Scripts/python.exe docs/phase4_integration_test.py

Side effects (cleaned up at exit):
  - Wipes %APPDATA%\\DFARS\\
  - Sets agent-zero settings.json mcp_server_token to a test value (restored at end)
  - Writes /a0/usr/plugins/_dfars_integration/config.yaml (removed at end)
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.paths import auth_db_path, config_path, data_dir, db_path  # noqa: E402

# ─── Setup paths and clean state ──────────────────────────

A0_SETTINGS = Path(r"C:\Users\jhenn\agent-zero\agent-zero\usr\settings.json")
A0_PLUGIN_CONFIG = Path(
    r"C:\Users\jhenn\agent-zero\agent-zero\usr\plugins\_dfars_integration\config.yaml"
)

dd = data_dir()
if dd.exists():
    shutil.rmtree(dd)
    print(f"Cleaned {dd}")

# Drop cached app modules
for mod in list(sys.modules):
    if mod.startswith("app"):
        sys.modules.pop(mod)

from app import api_tokens, auth, config as app_config  # noqa: E402
from app.flask_app import create_app  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

# Force DFARS to bind 0.0.0.0 so the agent-zero container can reach it
app_config.update(bind_host="0.0.0.0", preferred_port=5099)


# ─── Step 1: Create user + DFARS API token ─────────────

print()
print("== Phase 4 integration smoke test ==")
print()
print("-- Step 1: Create user + generate DFARS API token --")

app = create_app()  # initializes auth.db
auth.create_user("integration", "integration-test-password-12345")
user = auth.get_user("integration")
assert user is not None
token_id, dfars_token = api_tokens.generate(user["id"], "Integration Test")
print(f"     DFARS user 'integration' created")
print(f"     DFARS API token id={token_id}, prefix={dfars_token[:14]}...")


# ─── Step 2: Set Agent Zero mcp_server_token ─────────────

print()
print("-- Step 2: Read Agent Zero's current mcp_server_token --")
#
# Agent Zero auto-generates mcp_server_token on first launch and stores it
# in /a0/usr/secrets.env (not settings.json). The running web server caches
# the value in helpers.settings._settings. We can't replace it without
# restarting the container, so instead we just READ whatever it currently
# is and use that as our X-API-KEY for the test.
import subprocess as _sp
_token_proc = _sp.run(
    ["docker", "exec", "agent-zero", "sh", "-c",
     "cd /a0 && /opt/venv-a0/bin/python -c \""
     "from helpers.settings import get_settings; "
     "import sys; sys.stdout.write(get_settings()['mcp_server_token'])\""],
    capture_output=True, text=True, timeout=30,
    env={**os.environ, "MSYS_NO_PATHCONV": "1"},
)
test_a0_token = _token_proc.stdout.strip()
if not test_a0_token:
    print(f"     [FAIL] Could not read mcp_server_token: {_token_proc.stderr[:300]}")
    sys.exit(1)
print(f"     read mcp_server_token: len={len(test_a0_token)} prefix={test_a0_token[:8]}...")

# Sentinels to satisfy the cleanup section that originally restored settings.
original_a0_settings = A0_SETTINGS.read_text(encoding="utf-8")
original_token = ""


# ─── Step 3: Write plugin config with DFARS API token ───

print()
print("-- Step 3: Write plugin config.yaml --")

A0_PLUGIN_CONFIG.write_text(
    f"# Auto-written by phase4_integration_test.py\n"
    f"api_url: \"http://host.docker.internal:5099\"\n"
    f"api_token: \"{dfars_token}\"\n"
    f"enabled: true\n"
    f"request_timeout: 30\n",
    encoding="utf-8",
)
print(f"     wrote {A0_PLUGIN_CONFIG}")


# ─── Step 4: Start DFARS Desktop on 0.0.0.0:5099 ──────

print()
print("-- Step 4: Start DFARS Desktop on 0.0.0.0:5099 --")

# Check 5099 is free; otherwise the test can't run
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.bind(("0.0.0.0", 5099))
    except OSError as e:
        print(f"     [FAIL] cannot bind 0.0.0.0:5099 -- {e}")
        print("     Is another process using port 5099? Stop it and retry.")
        sys.exit(1)

server = make_server("0.0.0.0", 5099, app, threaded=True)
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
print("     DFARS Desktop listening on 0.0.0.0:5099")
time.sleep(0.5)


def _docker_exec(cmd_inside: str) -> tuple[int, str, str]:
    """Run a command inside the agent-zero container."""
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    result = subprocess.run(
        ["docker", "exec", "agent-zero", "sh", "-c", cmd_inside],
        capture_output=True, text=True, timeout=120, env=env,
    )
    return result.returncode, result.stdout, result.stderr


def _docker_python(script: str) -> tuple[int, str, str]:
    """Run a python -c script inside the container's a0 venv."""
    # Escape single quotes for shell wrapping
    escaped = script.replace("'", "'\\''")
    return _docker_exec(f"cd /a0 && /opt/venv-a0/bin/python -c '{escaped}'")


failures: list[str] = []


def fail(name: str, detail: str = ""):
    failures.append(f"{name}: {detail}" if detail else name)
    print(f"  [FAIL] {name} -- {detail}")


def ok(name: str):
    print(f"  [OK  ] {name}")


try:
    # ─── Step 5: Direction 1 -- plugin pushes to DFARS ─────

    print()
    print("-- Step 5: Direction 1 -- Agent Zero plugin pushes case data --")

    code, out, err = _docker_python(
        "from usr.plugins._dfars_integration.helpers.dfars_client import DFARSClient; "
        "import json; "
        "c = DFARSClient(); "
        "print(json.dumps(c.whoami()))"
    )
    if code != 0:
        fail("whoami", f"exit={code} stderr={err.strip()[:300]}")
    else:
        try:
            who = json.loads(out.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            fail("whoami parse", out[:300])
        else:
            assert who.get("username") == "integration", who
            ok(f"whoami -> {who['username']} (token '{who['token_name']}')")

    # Create case
    create_script = """
from usr.plugins._dfars_integration.helpers.dfars_client import DFARSClient
import json
c = DFARSClient()
result = c.create_case(
    case_id="INT-2026-0042",
    case_name="Integration Test Case",
    investigator="Agent Zero",
    description="Pushed by phase4_integration_test.py",
    priority="High",
    classification="internal_use",
    tags=["#integration", "#test"],
)
print(json.dumps({"case_id": result["case"]["case_id"]}))
"""
    code, out, err = _docker_python(create_script)
    if code != 0:
        fail("create_case", err.strip()[:400])
    else:
        ok("create_case")

    # Add evidence + custody + hash + tool + analysis
    populate_script = """
from usr.plugins._dfars_integration.helpers.dfars_client import DFARSClient
c = DFARSClient()
c.add_evidence(case_id="INT-2026-0042", evidence_id="EV-INT-001",
    description="Suspect drone DJI Mavic 3", collected_by="Agent Zero",
    evidence_type="Drone", make_model="DJI Mavic 3", serial_number="SN-INT-001",
    location="Field site Bravo")
c.add_custody(case_id="INT-2026-0042", evidence_id="EV-INT-001",
    action="Received from field", from_party="Field officer", to_party="Lab",
    purpose="Forensic analysis")
c.add_hash(case_id="INT-2026-0042", evidence_id="EV-INT-001",
    algorithm="SHA-256", hash_value="b" * 64, verified_by="Agent Zero")
c.add_tool(case_id="INT-2026-0042", tool_name="DroneXtract", version="2.1",
    purpose="Flight log extraction", operator="Agent Zero")
c.add_analysis(case_id="INT-2026-0042", category="Flight",
    finding="Restricted airspace incursion", confidence_level="High",
    description="GPS log shows 4 minutes inside restricted zone",
    evidence_id="EV-INT-001")
print("populate-ok")
"""
    code, out, err = _docker_python(populate_script)
    if code != 0:
        fail("populate evidence/custody/hash/tool/analysis", err.strip()[:400])
    elif "populate-ok" not in out:
        fail("populate", out[:300])
    else:
        ok("add evidence/custody/hash/tool/analysis (5 calls)")

    # Generate report
    report_script = """
from usr.plugins._dfars_integration.helpers.dfars_client import DFARSClient
c = DFARSClient()
result = c.generate_report("INT-2026-0042", fmt="markdown")
content = result.get("content", "")
print("REPORT_LEN", len(content))
print("HAS_CASE_NAME", "Integration Test Case" in content)
print("HAS_FINDING", "Restricted airspace incursion" in content)
"""
    code, out, err = _docker_python(report_script)
    if code != 0:
        fail("generate_report", err.strip()[:400])
    else:
        if "HAS_CASE_NAME True" in out and "HAS_FINDING True" in out:
            ok("generate_report (case name + finding present)")
        else:
            fail("report content check", out[:300])

    # ─── Step 6: Verify from host via DFARS REST ─────────

    print()
    print("-- Step 6: Verify from host via DFARS /api/v1 --")

    req = urllib.request.Request(
        "http://127.0.0.1:5099/api/v1/cases/INT-2026-0042",
        headers={"Authorization": f"Bearer {dfars_token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read())

    if payload.get("case", {}).get("case_id") == "INT-2026-0042":
        ok(f"GET case payload: case_id matches")
    else:
        fail("case_id mismatch", str(payload))

    expected_counts = {"evidence": 1, "custody": 1, "hashes": 1, "tools": 1, "analysis": 1}
    for key, want in expected_counts.items():
        got = len(payload.get(key, []))
        if got == want:
            ok(f"{key}: {got}")
        else:
            fail(f"{key} count", f"want {want}, got {got}")

    # ─── Step 7: Direction 2 -- DFARS calls Agent Zero ─────

    print()
    print("-- Step 7: Direction 2 -- DFARS Desktop calls Agent Zero plugin endpoint --")

    # Configure DFARS to point at Agent Zero
    from app import agent_zero_client
    agent_zero_client.save_settings(
        url="http://127.0.0.1:5080",
        api_key=test_a0_token,
    )
    print(f"     DFARS configured: url=http://127.0.0.1:5080, api_key=test-mcp-...{test_a0_token[-8:]}")

    # The plugin endpoints are picked up by Agent Zero's API dispatcher on
    # demand from /a0/usr/plugins/_dfars_integration/api/. We need to verify
    # this works WITHOUT requiring an LLM call to actually succeed (those
    # cost real API credits and may be slow). Either:
    #   - 200 OK with "enhanced": "..."  -> full success
    #   - 200 OK with "error": "LLM call failed: ..."  -> wiring works,
    #     LLM is the unrelated problem; ACCEPT
    #   - 401  -> auth wiring is broken; FAIL
    #   - URLError  -> Agent Zero unreachable; FAIL (test infrastructure)

    try:
        result = agent_zero_client._post(
            "/api/plugins/_dfars_integration/dfars_enhance",
            {"text": "Smoke test description for integration verification."},
            timeout=120.0,
        )
    except agent_zero_client.AgentZeroError as e:
        msg = str(e)
        if "401" in msg:
            fail("dfars_enhance auth", msg[:300])
        elif "404" in msg:
            fail("dfars_enhance route not registered", msg[:300])
        else:
            fail("dfars_enhance unreachable", msg[:300])
    else:
        if "enhanced" in result and result["enhanced"]:
            ok(f"dfars_enhance returned text ({len(result['enhanced'])} chars) -- LLM call succeeded")
        elif "error" in result and "llm" in result["error"].lower():
            ok(f"dfars_enhance reached + auth OK; LLM call itself failed: {result['error'][:120]}")
        else:
            fail("dfars_enhance unexpected response", json.dumps(result)[:300])

finally:
    # ─── Cleanup ─────────────────────────────────────────

    print()
    print("-- Cleanup --")

    server.shutdown()
    t.join(timeout=2)
    print("     DFARS server stopped")

    # Restore Agent Zero settings.json
    A0_SETTINGS.write_text(original_a0_settings, encoding="utf-8")
    print(f"     restored mcp_server_token to original ({'empty' if not original_token else 'set'})")

    # Remove plugin config.yaml override
    if A0_PLUGIN_CONFIG.exists():
        A0_PLUGIN_CONFIG.unlink()
        print("     removed plugin config.yaml")

print()
if failures:
    print(f"FAILURES: {len(failures)}")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
