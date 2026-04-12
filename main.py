"""
DFARS Desktop - application entry point.

Starts the embedded Flask server on a random localhost port in a
background thread, waits for it to respond, and then opens a PyWebView
window pointing at it. Closing the window shuts the whole process down.
"""

from __future__ import annotations

import logging
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import webview
from werkzeug.serving import make_server

from app import __version__, config as app_config
from app.flask_app import create_app
from app.paths import ensure_data_tree, logs_dir


# ─── Logging ────────────────────────────────────────────────


def _setup_logging() -> None:
    """Configure application logging to the user logs directory."""
    ensure_data_tree()
    log_path = logs_dir() / "dfars-desktop.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Quiet werkzeug's per-request access log noise in the desktop app
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ─── Flask server wrapper ──────────────────────────────────


class FlaskServerThread(threading.Thread):
    """A stoppable Werkzeug server running in a background thread."""

    def __init__(self, app, host: str = "127.0.0.1", port: int = 0):
        super().__init__(daemon=True, name="dfars-flask")
        self._server = make_server(host, port, app, threaded=True)
        self._ctx = app.app_context()
        self._ctx.push()
        # If port=0 was requested, `make_server` has assigned a real one
        self.host = host
        self.port = self._server.server_address[1]

    @property
    def url(self) -> str:
        # PyWebView always points at loopback regardless of bind host —
        # the Flask server may be listening on 0.0.0.0 to accept Docker
        # traffic, but the desktop window itself only ever needs loopback.
        display_host = "127.0.0.1" if self.host == "0.0.0.0" else self.host
        return f"http://{display_host}:{self.port}"

    def run(self) -> None:
        logging.info("Flask server listening on %s", self.url)
        self._server.serve_forever()

    def shutdown(self) -> None:
        logging.info("Shutting down Flask server")
        self._server.shutdown()


def _try_bind(host: str, port: int) -> bool:
    """Return True if host:port is currently free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _pick_free_port(host: str = "127.0.0.1") -> int:
    """Ask the OS for a free random port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _resolve_bind_port(host: str, preferred: int) -> int:
    """
    Try to bind the preferred port; on failure fall back to a random one.

    Why this matters: Agent Zero (and any other external integration) needs
    a stable, predictable address to push data to. A random port on every
    launch would force users to reconfigure their integrations constantly.
    The fallback exists for the rare case where 5099 is already in use.
    """
    if _try_bind(host, preferred):
        return preferred
    fallback = _pick_free_port(host)
    logging.warning(
        "Preferred port %d unavailable, using random port %d. "
        "External integrations may need to be reconfigured.",
        preferred, fallback,
    )
    return fallback


def _wait_until_ready(url: str, timeout: float = 10.0) -> bool:
    """Poll the health endpoint until it returns 200 or timeout elapses."""
    deadline = time.monotonic() + timeout
    health_url = f"{url}/api/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(0.1)
    return False


# ─── Main ───────────────────────────────────────────────────


def main() -> int:
    _setup_logging()
    logging.info("Starting DFARS Desktop v%s", __version__)

    paths = ensure_data_tree()
    logging.info("Data directory: %s", paths["data_dir"])

    try:
        app = create_app()
    except Exception:
        logging.exception("Failed to initialize Flask app")
        return 1

    cfg = app_config.load()
    bind_host = cfg.get("bind_host") or "127.0.0.1"
    preferred_port = int(cfg.get("preferred_port") or 5099)
    bind_port = _resolve_bind_port(bind_host, preferred_port)

    server = FlaskServerThread(app, host=bind_host, port=bind_port)
    server.start()

    # Persist the actual port so external tools (e.g. Agent Zero plugin)
    # can discover where DFARS Desktop is listening.
    app_config.update(actual_port=server.port)
    logging.info(
        "Listening on %s:%d (preferred=%d, display=%s)",
        bind_host, server.port, preferred_port, server.url,
    )

    if not _wait_until_ready(server.url):
        logging.error("Flask server did not become ready in time")
        server.shutdown()
        return 1

    icon_path = Path(__file__).parent / "app" / "static" / "dfars.ico"

    try:
        window = webview.create_window(
            title=f"DFARS Desktop v{__version__}",
            url=server.url,
            width=1400,
            height=900,
            min_size=(1000, 700),
            background_color="#1a1c20",
            confirm_close=False,
        )
        # Window icon: PyWebView reads it from the OS on Windows; setting
        # it via the EdgeChromium backend isn't directly supported at the
        # window level but PyInstaller's icon= bakes it into the .exe (Phase 5).
        _ = icon_path

        webview.start(debug=False)
    except Exception:
        logging.exception("PyWebView window failed")
        return 1
    finally:
        server.shutdown()

    logging.info("DFARS Desktop exited cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
