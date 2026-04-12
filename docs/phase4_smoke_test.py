"""
Phase 4 smoke test — DFARS REST API + token management.

Verifies:
  1. Setup and login (session-based UI)
  2. Generate API token via Security page (plaintext shown once)
  3. Bearer-token whoami round-trip
  4. Missing/invalid/wrong-prefix tokens are rejected (401)
  5. Create case via API (returns full payload)
  6. Add evidence/custody/hash/tool/analysis via API
  7. PATCH case to update status + tags
  8. GET case returns the full populated state
  9. Generate report via API (markdown + json + saved-to-disk)
  10. Edit case via UI form (browser-style POST)
  11. Revoke token, verify it stops working
  12. Token entry is cleaned out of api_tokens.list_for_user
"""
from __future__ import annotations

import http.cookiejar
import json
import re
import shutil
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.paths import auth_db_path, config_path, data_dir, db_path  # noqa: E402

# Clean slate
d = data_dir()
if d.exists():
    shutil.rmtree(d)
    print(f"Cleaned {d}")

# Drop cached app modules so a fresh app loads
for mod in list(sys.modules):
    if mod.startswith("app"):
        sys.modules.pop(mod)

from app.flask_app import create_app  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

app = create_app()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
server = make_server("127.0.0.1", port, app, threaded=True)
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
base = f"http://127.0.0.1:{port}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def make_session_client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPCookieProcessor(jar)
    )


sess = make_session_client()
failures = []


def req(opener, path, method="GET", data=None, json_body=None,
        headers=None, expect=None, check_body=None, label=""):
    url = base + path
    hdrs = dict(headers or {})
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
        r = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    else:
        r = urllib.request.Request(url, method=method, headers=hdrs)
    try:
        resp = opener.open(r, timeout=10)
        code, body, response_hdrs = resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        code, body, response_hdrs = e.code, e.read(), dict(e.headers)

    ok = True
    if expect is not None and code != expect:
        ok = False
    if check_body is not None and not check_body(body):
        ok = False

    mark = "OK  " if ok else "FAIL"
    extra = ""
    if code in (301, 302, 303, 307, 308):
        extra = f" -> {response_hdrs.get('Location', '')}"
    name = label or path
    print(f"  [{mark}] {method:6s} {name:55s} -> {code}{extra}")
    if not ok:
        failures.append((name, method, expect, code, body[:300]))
    return code, body, response_hdrs


try:
    print()
    print("-- Setup user + login --")
    req(sess, "/auth/setup", "POST", data={
        "username": "tester",
        "password": "phase4-smoke-test-password",
        "password_confirm": "phase4-smoke-test-password",
    }, expect=302)

    print()
    print("-- 1: Generate API token from Security page --")
    req(sess, "/auth/tokens/new", "POST", data={"name": "Smoke Test"}, expect=302)
    code, body, _ = req(sess, "/auth/tokens/show", expect=200,
                        label="GET /auth/tokens/show (one-time display)")
    m = re.search(rb'value="(dfars_[A-Za-z0-9_\-]+)"', body)
    assert m, f"plaintext token not found in /auth/tokens/show body[:500]={body[:500]!r}"
    plaintext_token = m.group(1).decode("ascii")
    print(f"     captured token: {plaintext_token[:14]}... ({len(plaintext_token)} chars)")

    bearer = {"Authorization": f"Bearer {plaintext_token}"}

    print()
    print("-- 2: Token revisit (should not show plaintext again) --")
    req(sess, "/auth/tokens/show", expect=302,
        label="GET /auth/tokens/show (second visit redirects)")

    print()
    print("-- 3: /api/v1/whoami round trip --")
    code, body, _ = req(sess, "/api/v1/whoami", "GET", headers=bearer, expect=200)
    who = json.loads(body)
    assert who["username"] == "tester", who
    assert who["token_name"] == "Smoke Test", who

    print()
    print("-- 4: Missing/invalid token paths are rejected --")
    req(sess, "/api/v1/whoami", expect=401, label="GET no Authorization header")
    req(sess, "/api/v1/whoami",
        headers={"Authorization": "Bearer dfars_invalid_token_xxx"},
        expect=401, label="GET wrong-prefix token")
    req(sess, "/api/v1/whoami",
        headers={"Authorization": "Bearer not-a-dfars-token"},
        expect=401, label="GET non-dfars token")

    print()
    print("-- 5: Create case via API --")
    code, body, _ = req(sess, "/api/v1/cases", "POST", json_body={
        "case_id": "AZ-2026-0042",
        "case_name": "Agent Zero Push Test",
        "investigator": "Agent Zero",
        "agency": "DFARS Internal",
        "description": "End-to-end test of REST API push",
        "status": "Active",
        "priority": "High",
        "classification": "internal_use",
        "tags": ["#test", "#smoke"],
    }, headers=bearer, expect=201)
    payload = json.loads(body)
    assert payload["case"]["case_id"] == "AZ-2026-0042"
    assert "#test" in payload["tags"]

    print()
    print("-- 5a: Duplicate create returns 409 --")
    req(sess, "/api/v1/cases", "POST", json_body={
        "case_id": "AZ-2026-0042",
        "case_name": "dup",
        "investigator": "x",
    }, headers=bearer, expect=409, label="POST duplicate case")

    print()
    print("-- 5b: Missing required fields returns 422 --")
    req(sess, "/api/v1/cases", "POST", json_body={
        "case_id": "AZ-2026-0099",
    }, headers=bearer, expect=422, label="POST missing fields")

    print()
    print("-- 6: Add evidence + custody + hash + tool + analysis --")
    code, body, _ = req(sess, "/api/v1/cases/AZ-2026-0042/evidence", "POST", json_body={
        "evidence_id": "EV-001",
        "description": "Suspect drone DJI Mavic 3",
        "collected_by": "Agent Zero",
        "evidence_type": "Drone",
        "make_model": "DJI Mavic 3",
        "serial_number": "SN12345",
        "collection_datetime": "2026-04-09T10:00:00",
        "location": "Field site Alpha",
    }, headers=bearer, expect=201)

    req(sess, "/api/v1/cases/AZ-2026-0042/custody", "POST", json_body={
        "evidence_id": "EV-001",
        "action": "Received from field",
        "from_party": "Field officer",
        "to_party": "Lab",
        "purpose": "Analysis",
        "custody_datetime": "2026-04-09T11:00:00",
    }, headers=bearer, expect=201)

    req(sess, "/api/v1/cases/AZ-2026-0042/hashes", "POST", json_body={
        "evidence_id": "EV-001",
        "algorithm": "SHA-256",
        "hash_value": "a" * 64,
        "verified_by": "Agent Zero",
        "verification_datetime": "2026-04-09T11:30:00",
    }, headers=bearer, expect=201)

    req(sess, "/api/v1/cases/AZ-2026-0042/tools", "POST", json_body={
        "tool_name": "DroneXtract",
        "version": "2.1",
        "purpose": "Flight log extraction",
        "operator": "Agent Zero",
    }, headers=bearer, expect=201)

    req(sess, "/api/v1/cases/AZ-2026-0042/analysis", "POST", json_body={
        "category": "Flight",
        "finding": "Unauthorized airspace incursion detected",
        "description": "GPS log shows entry into restricted zone at 10:42",
        "confidence_level": "High",
        "evidence_id": "EV-001",
    }, headers=bearer, expect=201)

    print()
    print("-- 6a: 404 paths --")
    req(sess, "/api/v1/cases/NOT-A-CASE", expect=404, headers=bearer, label="GET missing case")
    req(sess, "/api/v1/cases/AZ-2026-0042/custody", "POST", json_body={
        "evidence_id": "DOES-NOT-EXIST",
        "action": "x", "from_party": "x", "to_party": "x",
    }, headers=bearer, expect=404, label="POST custody for missing evidence")

    print()
    print("-- 7: PATCH case to update status + tags --")
    code, body, _ = req(sess, "/api/v1/cases/AZ-2026-0042", "PATCH", json_body={
        "status": "Closed",
        "priority": "Critical",
        "tags": ["#closed", "#test"],
    }, headers=bearer, expect=200)
    payload = json.loads(body)
    assert payload["case"]["status"] == "Closed", payload["case"]
    assert payload["case"]["priority"] == "Critical", payload["case"]
    assert set(payload["tags"]) == {"#closed", "#test"}, payload["tags"]

    print()
    print("-- 8: GET case returns full populated state --")
    code, body, _ = req(sess, "/api/v1/cases/AZ-2026-0042", "GET",
                        headers=bearer, expect=200)
    payload = json.loads(body)
    assert len(payload["evidence"]) == 1
    assert len(payload["custody"]) == 1
    assert len(payload["hashes"]) == 1
    assert len(payload["tools"]) == 1
    assert len(payload["analysis"]) == 1
    assert payload["stats"]["evidence_count"] == 1

    print()
    print("-- 9: Generate report (markdown, json, saved) --")
    code, body, _ = req(sess, "/api/v1/cases/AZ-2026-0042/report?format=markdown",
                        headers=bearer, expect=200)
    md = json.loads(body)
    assert "# Agent Zero Push Test" in md["content"], md["content"][:200]
    assert "Unauthorized airspace incursion" in md["content"]

    code, body, _ = req(sess, "/api/v1/cases/AZ-2026-0042/report?format=json",
                        headers=bearer, expect=200)
    js = json.loads(body)
    inner = json.loads(js["content"])
    assert inner["case"]["case_id"] == "AZ-2026-0042"

    code, body, _ = req(sess, "/api/v1/cases/AZ-2026-0042/report?format=markdown&save=true",
                        headers=bearer, expect=200)
    saved = json.loads(body)
    assert "saved_path" in saved and Path(saved["saved_path"]).exists()
    print(f"     saved report: {Path(saved['saved_path']).name}")

    print()
    print("-- 10: Edit case via UI form (browser-style POST) --")
    req(sess, "/case/AZ-2026-0042/edit", "POST", data={
        "case_name": "Agent Zero Push Test (edited)",
        "description": "Edited via UI form",
        "agency": "DFARS Internal",
        "status": "Active",
        "priority": "Medium",
        "classification": "internal_use",
        "tags": "#edited, #ui",
    }, expect=302)
    code, body, _ = req(sess, "/api/v1/cases/AZ-2026-0042", headers=bearer, expect=200)
    payload = json.loads(body)
    assert payload["case"]["case_name"] == "Agent Zero Push Test (edited)", payload["case"]
    assert payload["case"]["status"] == "Active", payload["case"]
    assert set(payload["tags"]) == {"#edited", "#ui"}, payload["tags"]

    print()
    print("-- 11: Revoke token, verify it stops working --")
    # Find the token row in the security page and revoke it
    code, body, _ = req(sess, "/auth/security", expect=200)
    m = re.search(rb'/auth/tokens/(\d+)/revoke', body)
    assert m, "no revoke link found in security page"
    token_id = int(m.group(1))
    req(sess, f"/auth/tokens/{token_id}/revoke", "POST", data={}, expect=302)
    req(sess, "/api/v1/whoami", headers=bearer, expect=401,
        label="GET /api/v1/whoami after revoke")

    print()
    print("-- 12: Verify token list is empty after revoke --")
    from app import api_tokens, auth as auth_mod
    user = auth_mod.get_user("tester")
    remaining = api_tokens.list_for_user(user["id"])
    assert remaining == [], f"expected empty list, got {remaining}"
    print(f"     api_tokens.list_for_user returned {len(remaining)} entries (expected 0)")

    print()
    print("-- AppData layout --")
    for name, path in [
        ("forensics.db", db_path()),
        ("auth.db", auth_db_path()),
        ("config.json", config_path()),
    ]:
        exists = path.exists()
        size = path.stat().st_size if exists else 0
        print(f"  {name:15s} {'OK' if exists else 'MISSING':8s} {size} bytes")
        if not exists:
            failures.append((str(path), "exists", True, False, b""))

    # config.json should now have actual_port written by main.py — but we
    # didn't run main.py here, just create_app(), so actual_port may be None.
    cfg = json.load(open(config_path()))
    print(f"  config.json: preferred_port={cfg.get('preferred_port')} "
          f"actual_port={cfg.get('actual_port')}")
    assert cfg.get("preferred_port") == 5099, "preferred_port default wrong"

finally:
    server.shutdown()
    t.join(timeout=2)

print()
if failures:
    print(f"FAILURES: {len(failures)}")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
