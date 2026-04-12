"""
Phase 3 smoke test — full MFA enrollment, two-step login, recovery codes,
and disable flow. Uses pyotp to generate valid TOTP codes synced to the
secret returned by the enrollment page.

Run with: ./.venv/Scripts/python.exe docs/phase3_smoke_test.py
"""
from __future__ import annotations

import http.cookiejar
import re
import shutil
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pyotp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.paths import auth_db_path, config_path, data_dir, db_path  # noqa: E402

# Clean slate so this is a deterministic first-run
d = data_dir()
if d.exists():
    shutil.rmtree(d)
    print(f"Cleaned {d}")

# Also clear any keyring state from prior runs so we exercise the fresh-key path
try:
    import keyring
    keyring.delete_password("DFARS Desktop", "totp_encryption_key")
    print("Cleared keyring entry from prior runs")
except Exception:
    pass

# Drop cached app modules
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
    return urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPCookieProcessor(jar)
    ), jar


sess, sess_jar = new_client()
failures = []


def req(opener, path, method="GET", data=None, expect=None, check_body=None):
    url = base + path
    if data is not None and method == "POST":
        body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(
            url, data=body, method="POST",
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
        failures.append((path, method, expect, code, body[:300]))
    return code, body, hdrs


try:
    print()
    print("-- Setup: create initial account (no MFA yet) --")
    req(sess, "/auth/setup", "POST", {
        "username": "jesse",
        "password": "correct-horse-battery-staple",
        "password_confirm": "correct-horse-battery-staple",
    }, expect=302)
    req(sess, "/", expect=200, check_body=lambda b: b"Dashboard" in b)

    print()
    print("-- Test 1: /auth/security shows MFA disabled --")
    _, body, _ = req(sess, "/auth/security", expect=200,
                     check_body=lambda b: b"Not enabled" in b)

    print()
    print("-- Test 2: GET /auth/mfa/setup yields a TOTP secret + QR --")
    _, body, _ = req(sess, "/auth/mfa/setup", expect=200)
    m = re.search(rb'value="([A-Z2-7]+)"\s+readonly\s+id="totp-secret"', body)
    assert m, f"TOTP secret not found in setup page. body[:500]={body[:500]!r}"
    secret = m.group(1).decode("ascii")
    print(f"     extracted TOTP secret: {secret[:6]}...{secret[-6:]} ({len(secret)} chars)")
    assert b"data:image/png;base64," in body, "QR code data URI missing"

    print()
    print("-- Test 3: POST a valid TOTP code, MFA enables, redirects to recovery codes --")
    valid_code = pyotp.TOTP(secret).now()
    _, body, hdrs = req(sess, "/auth/mfa/setup", "POST", {"code": valid_code}, expect=302)
    assert "/auth/mfa/recovery-codes" in hdrs.get("Location", ""), (
        f"Expected recovery-codes redirect, got {hdrs.get('Location')}"
    )

    print()
    print("-- Test 4: Recovery codes are shown ONCE --")
    _, body, _ = req(sess, "/auth/mfa/recovery-codes", expect=200)
    codes = re.findall(rb'<div class="fs-5 my-1">([a-f0-9]+-[a-f0-9]+)</div>', body)
    codes = [c.decode("ascii") for c in codes]
    assert len(codes) == 10, f"Expected 10 recovery codes, got {len(codes)}"
    print(f"     captured {len(codes)} recovery codes (e.g. {codes[0]}, {codes[1]}, ...)")

    # Visiting recovery-codes again should NOT show them
    _, body, _ = req(sess, "/auth/mfa/recovery-codes", expect=302,
                     check_body=lambda b: True)

    print()
    print("-- Test 5: /auth/security now shows MFA enabled with 10 codes --")
    _, body, _ = req(sess, "/auth/security", expect=200)
    assert b"Enabled" in body, "Security page should show MFA enabled"
    assert b"10 unused recovery codes" in body, "Should show 10 unused recovery codes"

    print()
    print("-- Test 6: Logout, then login with password requires MFA step --")
    req(sess, "/auth/logout", expect=302)
    _, _, hdrs = req(sess, "/auth/login", "POST", {
        "username": "jesse", "password": "correct-horse-battery-staple",
    }, expect=302)
    assert "/auth/mfa/verify" in hdrs.get("Location", ""), (
        f"Expected MFA verify redirect, got {hdrs.get('Location')}"
    )

    # Try accessing dashboard during pending MFA — should bounce to verify
    _, _, hdrs = req(sess, "/", expect=302)
    assert "/auth/mfa/verify" in hdrs.get("Location", "")

    print()
    print("-- Test 7: Wrong TOTP code is rejected --")
    req(sess, "/auth/mfa/verify", "POST", {"code": "000000"}, expect=200,
        check_body=lambda b: b"Invalid authentication code" in b)

    print()
    print("-- Test 8: Correct TOTP code completes login --")
    code_now = pyotp.TOTP(secret).now()
    _, _, hdrs = req(sess, "/auth/mfa/verify", "POST", {"code": code_now}, expect=302)
    assert hdrs.get("Location", "").endswith("/"), (
        f"Expected dashboard redirect after MFA, got {hdrs.get('Location')}"
    )
    req(sess, "/", expect=200)

    print()
    print("-- Test 9: Logout, login with password, redeem a recovery code --")
    req(sess, "/auth/logout", expect=302)
    req(sess, "/auth/login", "POST", {
        "username": "jesse", "password": "correct-horse-battery-staple",
    }, expect=302)

    recovery_to_use = codes[0]
    _, _, hdrs = req(sess, "/auth/mfa/verify", "POST", {
        "use_recovery": "1", "code": recovery_to_use,
    }, expect=302)
    assert hdrs.get("Location", "").endswith("/"), (
        f"Expected dashboard redirect after recovery, got {hdrs.get('Location')}"
    )
    req(sess, "/", expect=200)

    print()
    print("-- Test 10: Used recovery code can NOT be reused --")
    req(sess, "/auth/logout", expect=302)
    req(sess, "/auth/login", "POST", {
        "username": "jesse", "password": "correct-horse-battery-staple",
    }, expect=302)
    req(sess, "/auth/mfa/verify", "POST", {
        "use_recovery": "1", "code": codes[0],   # already redeemed
    }, expect=200, check_body=lambda b: b"Invalid recovery code" in b)
    # Use a different (still-unused) code to recover
    _, _, hdrs = req(sess, "/auth/mfa/verify", "POST", {
        "use_recovery": "1", "code": codes[1],
    }, expect=302)
    assert hdrs.get("Location", "").endswith("/")

    print()
    print("-- Test 11: Recovery code count is now 8 --")
    _, body, _ = req(sess, "/auth/security", expect=200)
    assert b"8 unused recovery codes" in body, (
        f"Expected '8 unused recovery codes' in security page"
    )

    print()
    print("-- Test 12: Disable MFA requires the password --")
    # Wrong password rejected
    req(sess, "/auth/mfa/disable", "POST", {"password": "wrong"}, expect=200,
        check_body=lambda b: b"Invalid" in b)
    # Correct password disables
    req(sess, "/auth/mfa/disable", "POST", {
        "password": "correct-horse-battery-staple",
    }, expect=302)

    print()
    print("-- Test 13: After disable, login is single-step again --")
    req(sess, "/auth/logout", expect=302)
    _, _, hdrs = req(sess, "/auth/login", "POST", {
        "username": "jesse", "password": "correct-horse-battery-staple",
    }, expect=302)
    assert hdrs.get("Location", "").endswith("/"), (
        f"Expected direct dashboard redirect, got {hdrs.get('Location')}"
    )

    print()
    print("-- Test 14: Re-enrollment generates a fresh secret --")
    _, body, _ = req(sess, "/auth/mfa/setup", expect=200)
    m = re.search(rb'value="([A-Z2-7]+)"\s+readonly\s+id="totp-secret"', body)
    new_secret = m.group(1).decode("ascii")
    assert new_secret != secret, "Re-enrollment must produce a new secret"
    print(f"     fresh secret: {new_secret[:6]}...{new_secret[-6:]} (different from original)")

    print()
    print("-- Test 15: Crypto key reachable via keyring --")
    try:
        import keyring
        stored = keyring.get_password("DFARS Desktop", "totp_encryption_key")
        if stored:
            print(f"     keyring entry present, length={len(stored)}")
        else:
            print("     [warn] keyring returned None — fallback keyfile may be in use")
    except Exception as e:
        print(f"     [warn] keyring access failed: {e}")

    print()
    print("-- Test 16: AppData layout intact --")
    for name, path in [
        ("forensics.db", db_path()),
        ("auth.db", auth_db_path()),
        ("config.json", config_path()),
    ]:
        exists = path.exists()
        size = path.stat().st_size if exists else 0
        status = "OK" if exists else "MISSING"
        print(f"  {name:15s} {status:8s} {size} bytes")
        if not exists:
            failures.append((str(path), "exists", True, False, b""))

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
