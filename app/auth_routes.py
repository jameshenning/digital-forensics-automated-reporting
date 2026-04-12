"""
DFARS Desktop - Authentication HTTP routes (Flask blueprint).

Handles the user-facing auth state machine:
- First launch:                no user → /auth/setup
- Subsequent launches:         user exists, not logged in → /auth/login
- Password OK, MFA required:   /auth/mfa/verify (session['mfa_pending'] set)
- Logged in:                   session['username'] set, requests flow to DFARS

The actual auth enforcement lives in flask_app.py as a before_request hook,
so every DFARS route is protected without per-route decorators.
"""

from __future__ import annotations

import base64
import io

import pyotp
import qrcode
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import api_tokens, audit, auth

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ─── Helpers ────────────────────────────────────────────────


def _qr_data_uri(provisioning_uri: str) -> str:
    """Render the otpauth:// URI as an inline base64 PNG data URI."""
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def _complete_login(username: str) -> None:
    """Promote a 'mfa_pending' session into a full login session."""
    session.pop("mfa_pending", None)
    session.pop("pending_totp_secret", None)
    session["username"] = username
    session.permanent = True


# ─── First-run setup ────────────────────────────────────────


@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """Create the single application user on first launch."""
    if auth.user_exists():
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if password != password_confirm:
            flash("Passwords do not match.", "danger")
        else:
            try:
                auth.create_user(username, password)
                session.clear()
                session["username"] = username.strip()
                session.permanent = True
                audit.log_auth(username.strip(), audit.SETUP_ACCOUNT, "Initial account created")
                flash(
                    f"Account created. Welcome to DFARS Desktop, "
                    f"{session['username']}.",
                    "success",
                )
                return redirect(url_for("dfars.dashboard"))
            except auth.AuthError as e:
                flash(str(e), "danger")

    return render_template("auth/setup.html")


# ─── Login (step 1: password) ──────────────────────────────


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Step 1: verify password. If MFA is enabled, redirect to step 2."""
    if not auth.user_exists():
        return redirect(url_for("auth.setup"))
    if session.get("username"):
        return redirect(url_for("dfars.dashboard"))
    if session.get("mfa_pending"):
        # User passed step 1 but bounced away — send them back to step 2
        return redirect(url_for("auth.mfa_verify"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            auth.verify_password(username, password)
        except auth.AccountLocked as e:
            audit.log_auth(username, audit.LOGIN_FAILED, f"Account locked: {e}")
            flash(str(e), "warning")
            return render_template("auth/login.html")
        except auth.AuthError as e:
            audit.log_auth(username, audit.LOGIN_FAILED, f"Bad credentials: {e}")
            flash(str(e), "danger")
            return render_template("auth/login.html")

        session.clear()
        if auth.is_mfa_enabled(username):
            session["mfa_pending"] = username
            session.permanent = True
            audit.log_auth(username, audit.LOGIN_SUCCESS, "Password OK, MFA pending")
            return redirect(url_for("auth.mfa_verify"))

        _complete_login(username)
        audit.log_auth(username, audit.LOGIN_SUCCESS, "Login complete (no MFA)")
        return redirect(url_for("dfars.dashboard"))

    return render_template("auth/login.html")


# ─── Login (step 2: MFA verify) ────────────────────────────


@auth_bp.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    """Step 2 of login: TOTP code, or fall back to a recovery code."""
    pending = session.get("mfa_pending")
    if not pending:
        # No password step completed → bounce to login
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        is_recovery = request.form.get("use_recovery") == "1"

        if is_recovery:
            if auth.verify_recovery_code(pending, code):
                _complete_login(pending)
                remaining = auth.remaining_recovery_codes(pending)
                audit.log_auth(pending, audit.MFA_RECOVERY_USED, f"{remaining} codes remaining")
                flash(
                    f"Signed in with a recovery code. {remaining} recovery "
                    f"code(s) remaining. Re-enroll MFA when convenient to "
                    f"replenish them.",
                    "warning",
                )
                return redirect(url_for("dfars.dashboard"))
            audit.log_auth(pending, audit.LOGIN_FAILED, "Invalid recovery code")
            flash("Invalid recovery code.", "danger")
        else:
            if auth.verify_totp(pending, code):
                _complete_login(pending)
                audit.log_auth(pending, audit.MFA_VERIFIED, "TOTP verified, login complete")
                return redirect(url_for("dfars.dashboard"))
            audit.log_auth(pending, audit.LOGIN_FAILED, "Invalid TOTP code")
            flash("Invalid authentication code.", "danger")

    return render_template("auth/mfa_verify.html", username=pending)


# ─── Logout ─────────────────────────────────────────────────


@auth_bp.route("/logout")
def logout():
    username = session.get("username") or session.get("mfa_pending")
    if username:
        audit.log_auth(username, audit.LOGOUT, "User logged out")
    session.clear()
    if username:
        flash(f"Goodbye, {username}. You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ─── Change password ────────────────────────────────────────


@auth_bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        new_confirm = request.form.get("new_password_confirm", "")

        if new != new_confirm:
            flash("New passwords do not match.", "danger")
        elif current == new:
            flash("New password must differ from the current password.", "danger")
        else:
            try:
                auth.update_password(username, current, new)
                audit.log_auth(username, audit.PASSWORD_CHANGED, "Password updated")
                flash("Password updated successfully.", "success")
                return redirect(url_for("dfars.dashboard"))
            except auth.AuthError as e:
                flash(str(e), "danger")

    return render_template("auth/change_password.html")


# ─── Security overview ─────────────────────────────────────


@auth_bp.route("/security")
def security():
    """Show MFA status and management links. Requires login."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    user = auth.get_user(username)
    tokens = api_tokens.list_for_user(user["id"]) if user else []

    from . import config as app_config, mailer, update_key
    cfg = app_config.load()
    az_url = cfg.get("agent_zero_url") or ""
    az_has_key = bool(cfg.get("agent_zero_api_key_encrypted"))

    from . import __version__
    pending_update = session.get("pending_update")

    return render_template(
        "auth/security.html",
        mfa_enabled=auth.is_mfa_enabled(username),
        recovery_remaining=auth.remaining_recovery_codes(username),
        api_tokens=tokens,
        agent_zero_url=az_url,
        agent_zero_has_key=az_has_key,
        current_version=__version__,
        update_url=cfg.get("update_url") or "",
        last_update_check=cfg.get("last_update_check"),
        update_disabled=update_key.is_placeholder(),
        pending_update=pending_update,
        smtp_server=cfg.get("smtp_server") or "",
        smtp_port=cfg.get("smtp_port") or 587,
        smtp_use_tls=cfg.get("smtp_use_tls", True),
        smtp_from_address=cfg.get("smtp_from_address") or "",
        smtp_username=cfg.get("smtp_username") or "",
        smtp_has_password=bool(cfg.get("smtp_password_encrypted")),
        smtp_configured=mailer.is_configured(),
    )


# ─── API token management ──────────────────────────────────


@auth_bp.route("/tokens/new", methods=["POST"])
def tokens_new():
    """Generate a new API token. Plaintext is shown ONCE on the next page."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    user = auth.get_user(username)
    if not user:
        return redirect(url_for("auth.login"))

    name = request.form.get("name", "").strip()
    if not name:
        flash("Token name is required.", "danger")
        return redirect(url_for("auth.security"))

    try:
        token_id, plaintext = api_tokens.generate(user["id"], name)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("auth.security"))

    audit.log_auth(username, audit.API_TOKEN_CREATED, f"Token '{name}' (id={token_id})")
    session["fresh_api_token"] = {"name": name, "plaintext": plaintext, "id": token_id}
    return redirect(url_for("auth.tokens_show"))


@auth_bp.route("/tokens/show")
def tokens_show():
    """Display a freshly-generated API token exactly once."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    fresh = session.pop("fresh_api_token", None)
    if not fresh:
        flash(
            "API tokens are only shown once, immediately after creation. "
            "Generate a new token if you need to recover access.",
            "warning",
        )
        return redirect(url_for("auth.security"))

    return render_template("auth/tokens_show.html", token=fresh)


@auth_bp.route("/tokens/<int:token_id>/revoke", methods=["POST"])
def tokens_revoke(token_id):
    """Permanently delete an API token."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))
    user = auth.get_user(username)
    if not user:
        return redirect(url_for("auth.login"))

    if api_tokens.revoke(token_id, user["id"]):
        audit.log_auth(username, audit.API_TOKEN_REVOKED, f"Token id={token_id}")
        flash("API token revoked.", "success")
    else:
        flash("Token not found.", "warning")
    return redirect(url_for("auth.security"))


# ─── Agent Zero one-click setup ───────────────────────────


@auth_bp.route("/agent-zero/auto-setup", methods=["POST"])
def agent_zero_auto_setup():
    """
    One-click Agent Zero connection:
    1. Generate a DFARS API token for Agent Zero
    2. Write the plugin config.yaml with the token
    3. Restart the Agent Zero Docker container
    4. Test the connection
    """
    import subprocess
    from pathlib import Path

    import yaml

    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    user = auth.get_user(username)
    if not user:
        return redirect(url_for("auth.login"))

    from . import config as app_config

    steps_log = []

    # Step 1: Generate API token
    try:
        # Revoke any existing "Agent Zero (auto)" tokens first
        existing_tokens = api_tokens.list_for_user(user["id"])
        for t in existing_tokens:
            if t.get("name") == "Agent Zero (auto)":
                api_tokens.revoke(t["id"], user["id"])
                steps_log.append("Revoked old auto-generated token.")

        token_id, plaintext = api_tokens.generate(user["id"], "Agent Zero (auto)")
        steps_log.append(f"Generated API token: Agent Zero (auto) (id={token_id})")
        audit.log_auth(username, audit.API_TOKEN_CREATED, f"Auto-setup: token 'Agent Zero (auto)' (id={token_id})")
    except Exception as e:
        flash(f"Failed to generate token: {e}", "danger")
        return redirect(url_for("auth.security"))

    # Step 2: Write plugin config.yaml
    cfg = app_config.load()
    dfars_port = cfg.get("actual_port") or cfg.get("preferred_port") or 5099

    plugin_dir = Path("C:/Users/jhenn/agent-zero/agent-zero/usr/plugins/_dfars_integration")
    config_path = plugin_dir / "config.yaml"

    plugin_config = {
        "api_url": f"http://host.docker.internal:{dfars_port}",
        "api_token": plaintext,
        "enabled": True,
        "request_timeout": 15,
    }

    try:
        config_path.write_text(
            yaml.dump(plugin_config, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        steps_log.append(f"Wrote plugin config to {config_path}")
    except Exception as e:
        flash(f"Token generated but failed to write plugin config: {e}. "
              f"Token plaintext (save it): {plaintext}", "danger")
        return redirect(url_for("auth.security"))

    # Step 3: Restart Agent Zero container
    try:
        result = subprocess.run(
            ["docker", "restart", "agent-zero"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            steps_log.append("Restarted agent-zero container.")
        else:
            steps_log.append(f"Container restart warning: {result.stderr.strip()}")
    except FileNotFoundError:
        steps_log.append("Docker not found — skip container restart. Restart manually.")
    except subprocess.TimeoutExpired:
        steps_log.append("Container restart timed out. It may still be restarting.")
    except Exception as e:
        steps_log.append(f"Container restart error: {e}")

    # Step 4: Wait a moment for container to come up, then test
    import time
    time.sleep(3)

    from . import agent_zero_client
    try:
        ok, msg = agent_zero_client.test_connection()
        if ok:
            steps_log.append(f"Connection verified: {msg}")
        else:
            steps_log.append(f"Connection test: {msg} (container may still be starting — try Test Connection in a few seconds)")
    except Exception as e:
        steps_log.append(f"Connection test skipped: {e}")

    audit.log_auth(username, audit.SETTINGS_CHANGED,
                   f"Agent Zero auto-setup completed: {'; '.join(steps_log)}")

    flash(
        "Agent Zero auto-setup complete: " + " → ".join(steps_log),
        "success",
    )
    return redirect(url_for("auth.security"))


# ─── Agent Zero connection settings ───────────────────────


@auth_bp.route("/agent-zero/save", methods=["POST"])
def agent_zero_save():
    """Save Agent Zero URL + API key (key encrypted via app.crypto)."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    from . import agent_zero_client

    url = (request.form.get("agent_zero_url") or "").strip()
    api_key = (request.form.get("agent_zero_api_key") or "").strip()

    if not url:
        flash("Agent Zero URL is required.", "danger")
        return redirect(url_for("auth.security"))

    try:
        agent_zero_client.save_settings(url, api_key or None)
        audit.log_auth(username, audit.SETTINGS_CHANGED, f"Agent Zero URL set to {url}" + (" + new API key" if api_key else ""))
        if api_key:
            flash("Agent Zero connection saved (URL + API key).", "success")
        else:
            flash("Agent Zero URL updated. Existing API key preserved.", "info")
    except Exception as e:
        flash(f"Failed to save Agent Zero settings: {e}", "danger")

    return redirect(url_for("auth.security"))


@auth_bp.route("/agent-zero/clear-key", methods=["POST"])
def agent_zero_clear_key():
    """Wipe the stored Agent Zero API key without touching the URL."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    from . import agent_zero_client
    agent_zero_client.clear_api_key()
    audit.log_auth(username, audit.SETTINGS_CHANGED, "Agent Zero API key cleared")
    flash("Agent Zero API key removed.", "success")
    return redirect(url_for("auth.security"))


@auth_bp.route("/agent-zero/test", methods=["POST"])
def agent_zero_test():
    """Ping Agent Zero with the saved settings and report the result."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    from . import agent_zero_client
    ok, message = agent_zero_client.test_connection()
    flash(
        f"Agent Zero: {message}",
        "success" if ok else "danger",
    )
    return redirect(url_for("auth.security"))


# ─── Email (SMTP) settings ────────────────────────────────


@auth_bp.route("/smtp/save", methods=["POST"])
def smtp_save():
    """Save SMTP email settings (password encrypted via app.crypto)."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    from . import mailer

    server = (request.form.get("smtp_server") or "").strip()
    port = int(request.form.get("smtp_port") or 587)
    use_tls = request.form.get("smtp_use_tls") == "1"
    from_address = (request.form.get("smtp_from_address") or "").strip()
    smtp_username = (request.form.get("smtp_username") or "").strip()
    password = (request.form.get("smtp_password") or "").strip()

    if not server or not from_address:
        flash("SMTP server and from-address are required.", "danger")
        return redirect(url_for("auth.security"))

    try:
        mailer.save_settings(server, port, use_tls, from_address, smtp_username, password or None)
        audit.log_auth(username, audit.SETTINGS_CHANGED,
                       f"SMTP configured: {server}:{port} from={from_address}"
                       + (" + new password" if password else ""))
        flash("Email settings saved." + (" Password updated." if password else " Existing password kept."), "success")
    except Exception as e:
        flash(f"Failed to save email settings: {e}", "danger")

    return redirect(url_for("auth.security"))


@auth_bp.route("/smtp/test", methods=["POST"])
def smtp_test():
    """Test SMTP connection with saved settings."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    from . import mailer
    ok, message = mailer.test_connection()
    flash(f"SMTP: {message}", "success" if ok else "danger")
    return redirect(url_for("auth.security"))


# ─── Updates ───────────────────────────────────────────────


@auth_bp.route("/updates/check", methods=["POST"])
def updates_check():
    """Manually check for a new release."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    from . import updater
    try:
        info = updater.check_for_update()
    except updater.UpdateError as e:
        flash(f"Update check failed: {e}", "danger")
        return redirect(url_for("auth.security"))

    if info.is_newer:
        flash(
            f"Update available: {info.version}. Click 'Install Update' to download.",
            "success",
        )
        # Stash for the install handler so we don't refetch
        session["pending_update"] = {
            "version": info.version,
            "notes": info.notes,
            "download_url": info.download_url,
            "sha256": info.sha256,
            "size_bytes": info.size_bytes,
        }
    else:
        flash(
            f"You are running the latest version ({info.version}).",
            "info",
        )
        session.pop("pending_update", None)

    return redirect(url_for("auth.security"))


@auth_bp.route("/updates/install", methods=["POST"])
def updates_install():
    """Download the pending update, verify it, and launch the installer."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    from . import updater
    pending = session.get("pending_update")
    if not pending:
        flash("No pending update. Click 'Check for Updates' first.", "warning")
        return redirect(url_for("auth.security"))

    info = updater.UpdateInfo(
        version=pending["version"],
        notes=pending.get("notes", ""),
        released_at="",
        download_url=pending["download_url"],
        sha256=pending["sha256"],
        size_bytes=int(pending.get("size_bytes") or 0),
        is_newer=True,
    )

    try:
        installer_path = updater.download_update(info)
        updater.apply_update(installer_path)
    except updater.UpdateError as e:
        flash(f"Install failed: {e}", "danger")
        return redirect(url_for("auth.security"))

    flash(
        f"Installer launched. DFARS Desktop will exit so the update can apply.",
        "success",
    )
    session.pop("pending_update", None)

    # Schedule a clean exit AFTER this response is delivered.
    # We can't sys.exit synchronously because Flask still needs to write
    # the redirect; instead, fire a delayed terminate.
    import threading, os
    def _delayed_exit():
        import time
        time.sleep(2.0)
        os._exit(0)
    threading.Thread(target=_delayed_exit, daemon=True).start()

    return redirect(url_for("auth.security"))


# ─── MFA enrollment ────────────────────────────────────────


@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    """Enroll a TOTP authenticator. Generates a fresh secret each visit."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    if auth.is_mfa_enabled(username):
        flash("MFA is already enabled. Disable it first to re-enroll.", "warning")
        return redirect(url_for("auth.security"))

    # Reuse a pending secret across the GET → POST transition so the QR
    # code matches the verification step. New secret on first GET only.
    if request.method == "GET" or "pending_totp_secret" not in session:
        session["pending_totp_secret"] = auth.generate_totp_secret()

    secret = session["pending_totp_secret"]
    provisioning_uri = auth.totp_provisioning_uri(username, secret)
    qr_data_uri = _qr_data_uri(provisioning_uri)

    if request.method == "POST":
        code = request.form.get("code", "")
        if not pyotp.TOTP(secret).verify(
            "".join(c for c in code if c.isdigit()),
            valid_window=auth.TOTP_VALID_WINDOW,
        ):
            flash(
                "That code didn't match. Make sure your authenticator clock "
                "is in sync and try the next code.",
                "danger",
            )
        else:
            auth.enable_mfa(username, secret)
            recovery_codes = auth.generate_recovery_codes(username)
            audit.log_auth(username, audit.MFA_ENABLED, f"TOTP enrolled, {len(recovery_codes)} recovery codes generated")
            session.pop("pending_totp_secret", None)
            # Stash codes in the session so the next page can show them
            # exactly once. The recovery_codes template pops them on display.
            session["fresh_recovery_codes"] = recovery_codes
            flash("MFA enabled. Save your recovery codes below.", "success")
            return redirect(url_for("auth.mfa_recovery_codes"))

    return render_template(
        "auth/mfa_setup.html",
        secret=secret,
        qr_data_uri=qr_data_uri,
    )


@auth_bp.route("/mfa/recovery-codes")
def mfa_recovery_codes():
    """
    Display the freshly-generated recovery codes ONCE. The session flag
    is popped here, so reloading or revisiting won't show them again.
    """
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    codes = session.pop("fresh_recovery_codes", None)
    if not codes:
        # Page was refreshed or accessed directly without enrollment context
        flash(
            "Recovery codes are only shown once, immediately after enrollment. "
            "Re-enroll MFA to generate a new set.",
            "warning",
        )
        return redirect(url_for("auth.security"))

    return render_template("auth/mfa_recovery_codes.html", codes=codes)


@auth_bp.route("/mfa/disable", methods=["GET", "POST"])
def mfa_disable():
    """Disable MFA. Requires the user's password."""
    username = session.get("username")
    if not username:
        return redirect(url_for("auth.login"))

    if not auth.is_mfa_enabled(username):
        flash("MFA is not currently enabled.", "info")
        return redirect(url_for("auth.security"))

    if request.method == "POST":
        password = request.form.get("password", "")
        try:
            auth.disable_mfa(username, password)
            audit.log_auth(username, audit.SETTINGS_CHANGED, "MFA disabled")
            flash("MFA disabled. Your account is now password-only.", "success")
            return redirect(url_for("auth.security"))
        except auth.AuthError as e:
            flash(str(e), "danger")

    return render_template("auth/mfa_disable.html")
