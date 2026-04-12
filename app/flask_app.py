"""
DFARS Desktop - Flask application factory.

Wires together:
- Persistent session secret (so logins survive restarts)
- Auth DB + forensics DB initialization
- Route blueprints: dfars (case management) + auth (login/setup/logout)
- Global before_request hook enforcing the auth state machine
"""

from __future__ import annotations

from datetime import timedelta

from flask import Flask, redirect, request, session, url_for

from . import auth, config
from .api_routes import api_bp
from .auth_routes import auth_bp
from .database import ForensicsDatabase
from .paths import db_path, ensure_data_tree, static_dir, templates_dir
from .report_generator import ForensicReportGenerator
from .routes import bp as dfars_bp


def create_app() -> Flask:
    """Create and configure the Flask application."""
    ensure_data_tree()

    app = Flask(
        __name__,
        static_folder=str(static_dir()),
        template_folder=str(templates_dir()),
    )

    # Persistent session secret — loaded from config.json, created on first run.
    # Without this, every app restart invalidates existing login sessions.
    app.secret_key = config.get_or_create_session_secret()
    app.permanent_session_lifetime = timedelta(days=7)

    # Session cookie hardening. We only ever serve on 127.0.0.1, so Secure
    # would block cookies over plain HTTP; leave it off but lock down the
    # other flags.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    # Initialize both databases up front so the first request isn't slow.
    auth.init_db()
    db = ForensicsDatabase(db_path())
    report_gen = ForensicReportGenerator(db)

    app.config["DFARS_DB"] = db
    app.config["DFARS_REPORT_GEN"] = report_gen

    # Register route blueprints
    app.register_blueprint(dfars_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    # ── Global auth gate ───────────────────────────────────
    #
    # Runs before every request. Enforces the state machine:
    #   no user exists                       → /auth/setup
    #   user exists, no session              → /auth/login
    #   password OK, awaiting MFA            → /auth/mfa/verify
    #   logged in                            → proceed
    #
    # Static files and the auth blueprint itself are allowed through
    # unconditionally so the login/setup/MFA pages can load their assets.
    @app.before_request
    def _require_auth():
        endpoint = request.endpoint or ""
        if endpoint == "static" or endpoint.startswith("auth."):
            return None
        # Health check is the desktop shell's readiness probe
        if endpoint == "dfars.health":
            return None
        # /api/v1/* uses bearer token auth, handled inside api_routes.py.
        # Skip the session-cookie gate so external integrations can call it.
        if endpoint and endpoint.startswith("api_v1."):
            return None

        if not auth.user_exists():
            return redirect(url_for("auth.setup"))
        if session.get("username"):
            return None
        if session.get("mfa_pending"):
            return redirect(url_for("auth.mfa_verify"))
        return redirect(url_for("auth.login"))

    return app
