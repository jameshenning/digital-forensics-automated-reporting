"""
Phase 2 smoke test — full auth state machine.

Run with: ./.venv/Scripts/python.exe docs/phase2_smoke_test.py

Verifies:
  1. Pristine state: redirects to /auth/setup
  2. POST setup creates user + logs in, dashboard accessible
  3. Signed-in user shows in navbar
  4. Logout clears session
  5. Setup blocked once a user exists
  6. Login with wrong password flashes error
  7. Login with correct password works
  8. Password change flow
  9. Lockout after 5 failed attempts
  10. AppData layout (forensics.db, auth.db, config.json)
"""
from __future__ import annotations

import http.cookiejar
import json
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

# Clean slate — force a pristine first-run experience
d = data_dir()
if d.exists():
    shutil.rmtree(d)
    print(f"Cleaned {d}")

# Drop any cached app.* modules so fresh paths are loaded
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


def new_client():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        NoRedirect(),
        urllib.request.HTTPCookieProcessor(jar),
    )
    return opener, jar


anon, anon_jar = new_client()
sess, sess_jar = new_client()

failures = []


def req(opener, path, method="GET", data=None, expect=None, check_body=None):
    url = base + path
    if data is not None and method == "POST":
        body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    else:
        r = urllib.request.Request(url, method=method)
    try:
        resp = opener.open(r, timeout=5)
        code, body, hdrs = resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        code, body, hdrs = e.code, e.read(), dict(e.headers)

    ok = True
    if expect is not None and code != expect:
        ok = False
    if check_body is not None and not check_body(body):
        ok = False

    mark = "OK  " if ok else "FAIL"
    extra = ""
    if code in (301, 302, 303, 307, 308):
        extra = f" -> {hdrs.get('Location', '')}"
    print(f"  [{mark}] {method:4s} {path:40s} -> {code}{extra}")
    if not ok:
        failures.append((path, method, expect, code, body[:200]))
    return code, body, hdrs


try:
    print()
    print("-- Test 1: pristine state forces /auth/setup --")
    _, _, hdrs = req(anon, "/", expect=302)
    assert "/auth/setup" in hdrs.get("Location", ""), (
        f"Expected setup redirect, got {hdrs.get('Location')}"
    )

    # DFARS routes also blocked
    req(anon, "/case/new", expect=302)

    # /auth/setup itself returns 200
    req(
        anon,
        "/auth/setup",
        expect=200,
        check_body=lambda b: b"Create Your Account" in b,
    )

    print()
    print("-- Test 2: create account via setup --")
    req(
        sess,
        "/auth/setup",
        "POST",
        {
            "username": "jesse",
            "password": "correct-horse-battery-staple",
            "password_confirm": "correct-horse-battery-staple",
        },
        expect=302,
    )

    # Now the session cookie should grant dashboard access
    req(sess, "/", expect=200, check_body=lambda b: b"Dashboard" in b)
    req(sess, "/case/new", expect=200, check_body=lambda b: b"New Case" in b)

    print()
    print("-- Test 3: signed-in user shows in navbar --")
    _, body, _ = req(sess, "/", expect=200)
    assert b"jesse" in body, "username missing from dashboard nav"

    print()
    print("-- Test 4: logout clears session --")
    req(sess, "/auth/logout", expect=302)
    _, _, hdrs = req(sess, "/", expect=302)
    assert "/auth/login" in hdrs.get("Location", ""), (
        f"Expected login redirect after logout, got {hdrs.get('Location')}"
    )

    print()
    print("-- Test 5: setup is blocked once a user exists --")
    _, _, hdrs = req(sess, "/auth/setup", expect=302)
    assert "/auth/login" in hdrs.get("Location", ""), (
        "setup should redirect to login when user exists"
    )

    print()
    print("-- Test 6: login with wrong password shows error --")
    req(
        sess,
        "/auth/login",
        "POST",
        {"username": "jesse", "password": "wrong-password-for-testing"},
        expect=200,
        check_body=lambda b: b"Invalid username or password" in b,
    )

    print()
    print("-- Test 7: login with correct password works --")
    req(
        sess,
        "/auth/login",
        "POST",
        {"username": "jesse", "password": "correct-horse-battery-staple"},
        expect=302,
    )
    req(sess, "/", expect=200)

    print()
    print("-- Test 8: password change --")
    req(
        sess,
        "/auth/change-password",
        "POST",
        {
            "current_password": "correct-horse-battery-staple",
            "new_password": "tr0ubadour-squirrel-lighthouse",
            "new_password_confirm": "tr0ubadour-squirrel-lighthouse",
        },
        expect=302,
    )

    # Old password should no longer work
    req(sess, "/auth/logout", expect=302)
    req(
        sess,
        "/auth/login",
        "POST",
        {"username": "jesse", "password": "correct-horse-battery-staple"},
        expect=200,
        check_body=lambda b: b"Invalid" in b,
    )
    # New password works
    req(
        sess,
        "/auth/login",
        "POST",
        {"username": "jesse", "password": "tr0ubadour-squirrel-lighthouse"},
        expect=302,
    )

    print()
    print("-- Test 9: lockout after 5 failed attempts --")
    req(sess, "/auth/logout", expect=302)
    for i in range(1, 6):
        req(
            sess,
            "/auth/login",
            "POST",
            {"username": "jesse", "password": f"wrong-try-{i}"},
            expect=200,
        )
    # 6th attempt with correct password should still be locked out
    _, body, _ = req(
        sess,
        "/auth/login",
        "POST",
        {"username": "jesse", "password": "tr0ubadour-squirrel-lighthouse"},
        expect=200,
    )
    if b"locked" not in body.lower():
        print(f"  [FAIL] lockout not triggered. body: {body[:300]!r}")
        failures.append(("lockout", "check", "locked", "not-locked", body[:200]))
    else:
        print("  [OK  ] lockout engaged correctly after 5 failures")

    print()
    print("-- Test 10: AppData layout --")
    checks = [
        ("forensics.db", db_path()),
        ("auth.db", auth_db_path()),
        ("config.json", config_path()),
    ]
    for name, path in checks:
        exists = path.exists()
        size = path.stat().st_size if exists else 0
        status = "OK" if exists else "MISSING"
        print(f"  {name:15s} {status:8s} {path} ({size} bytes)")
        if not exists:
            failures.append((str(path), "exists", True, False, b""))

    # config.json should contain a session_secret
    with open(config_path()) as f:
        cfg = json.load(f)
    assert cfg.get("session_secret"), "session_secret missing from config.json"
    assert len(cfg["session_secret"]) == 64, "session_secret wrong length"
    print(
        f"  config.json session_secret: {cfg['session_secret'][:8]}... (persistent)"
    )

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
