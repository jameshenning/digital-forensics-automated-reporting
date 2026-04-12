"""
DFARS Desktop - Direct SMTP email sender.

Uses Python's built-in smtplib + email.mime modules (no external deps).
SMTP credentials are stored Fernet-encrypted in config.json via app.crypto.

All sends are logged to the case audit trail and the Shares & Prints section.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from . import config as app_config, crypto

log = logging.getLogger(__name__)


class MailerError(Exception):
    """Raised on any email sending failure."""


def _load_smtp_settings() -> dict:
    cfg = app_config.load()
    password: Optional[str] = None
    enc = cfg.get("smtp_password_encrypted")
    if enc:
        try:
            password = crypto.decrypt(enc).decode("utf-8")
        except Exception as e:
            log.warning("Failed to decrypt SMTP password: %s", e)
    return {
        "server": cfg.get("smtp_server") or "",
        "port": int(cfg.get("smtp_port") or 587),
        "use_tls": cfg.get("smtp_use_tls", True),
        "from_address": cfg.get("smtp_from_address") or "",
        "username": cfg.get("smtp_username") or "",
        "password": password or "",
    }


def is_configured() -> bool:
    s = _load_smtp_settings()
    return bool(s["server"] and s["from_address"])


def save_settings(
    server: str,
    port: int,
    use_tls: bool,
    from_address: str,
    username: str,
    password: Optional[str],
) -> None:
    updates = {
        "smtp_server": server.strip(),
        "smtp_port": port,
        "smtp_use_tls": use_tls,
        "smtp_from_address": from_address.strip(),
        "smtp_username": username.strip(),
    }
    if password:
        updates["smtp_password_encrypted"] = crypto.encrypt(password.strip())
    app_config.update(**updates)


def test_connection() -> tuple[bool, str]:
    """Try connecting to the SMTP server. Returns (ok, message)."""
    if not is_configured():
        return False, "SMTP server or from-address not configured."
    s = _load_smtp_settings()
    try:
        conn = _connect(s)
        conn.quit()
        return True, f"Connected to {s['server']}:{s['port']} successfully."
    except Exception as e:
        return False, str(e)


def _connect(s: dict) -> smtplib.SMTP:
    """Establish an SMTP connection with the stored settings."""
    try:
        if s["use_tls"]:
            conn = smtplib.SMTP(s["server"], s["port"], timeout=30)
            conn.ehlo()
            conn.starttls(context=ssl.create_default_context())
            conn.ehlo()
        else:
            conn = smtplib.SMTP(s["server"], s["port"], timeout=30)
            conn.ehlo()
    except Exception as e:
        raise MailerError(f"Could not connect to {s['server']}:{s['port']}: {e}")

    if s["username"] and s["password"]:
        try:
            conn.login(s["username"], s["password"])
        except smtplib.SMTPAuthenticationError as e:
            conn.quit()
            raise MailerError(
                f"SMTP authentication failed for {s['username']}: {e}. "
                f"Check your username/password. For Gmail, use an App Password."
            )
        except Exception as e:
            conn.quit()
            raise MailerError(f"SMTP login error: {e}")

    return conn


def send_record(
    to_address: str,
    case_id: str,
    case_name: str,
    record_type: str,
    record_summary: str,
    md_file_path: str,
    file_hash: str,
    narrative: str,
    sender_name: str,
) -> None:
    """
    Send a DFARS record export as an email with the .md file attached.

    Subject format: [DFARS] CASE-ID — Case Name — Record Type: Summary
    """
    if not is_configured():
        raise MailerError(
            "SMTP is not configured. Go to Security > Email Settings to set up."
        )

    s = _load_smtp_settings()

    # Build subject line with case number, name, and record type
    type_labels = {
        "evidence": "Evidence",
        "custody": "Chain of Custody",
        "hash": "Hash Verification",
        "tool": "Tool Usage",
        "analysis": "Analysis Note",
    }
    type_label = type_labels.get(record_type, record_type.title())
    subject = f"[DFARS] {case_id} — {case_name} — {type_label}: {record_summary}"

    # Build the message
    msg = MIMEMultipart()
    msg["From"] = s["from_address"]
    msg["To"] = to_address
    msg["Subject"] = subject

    body = (
        f"DFARS Desktop — Record Export\n"
        f"{'=' * 50}\n\n"
        f"Case: {case_id} — {case_name}\n"
        f"Record: {type_label}\n"
        f"Summary: {record_summary}\n"
        f"Sent by: {sender_name}\n\n"
        f"Narrative:\n{narrative}\n\n"
        f"{'=' * 50}\n"
        f"Attached file SHA-256: {file_hash}\n\n"
        f"This email was sent directly from DFARS Desktop.\n"
        f"The attached .md file is the official record export.\n"
        f"Verify integrity by comparing the SHA-256 hash above\n"
        f"with the hash at the bottom of the attached document.\n"
    )
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # Attach the .md file
    md_path = Path(md_file_path)
    if not md_path.exists():
        raise MailerError(f"Export file not found: {md_file_path}")

    attachment = MIMEBase("text", "markdown")
    attachment.set_payload(md_path.read_bytes())
    encoders.encode_base64(attachment)
    attachment.add_header(
        "Content-Disposition",
        f"attachment; filename={md_path.name}",
    )
    msg.attach(attachment)

    # Send
    try:
        conn = _connect(s)
        conn.sendmail(s["from_address"], [to_address], msg.as_string())
        conn.quit()
    except MailerError:
        raise
    except Exception as e:
        raise MailerError(f"Failed to send email: {e}")
