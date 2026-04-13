/// Audit trail — mirrors v1's `app/audit.py`.
///
/// v1 writes pipe-delimited lines to flat `.txt` files under
/// `%APPDATA%\DFARS\admin\audit\`.  v2 preserves the same directory and
/// format so the audit files can be opened by both versions.
///
/// Line format (one per action, UTF-8):
///   YYYY-MM-DDTHH:MM:SS.ffffff | username | ACTION_CODE | detail text
///
/// Auth actions go to `auth_audit.txt`.
/// Case actions go to `cases\<case_id>_audit.txt`.
///
/// Many action constants and `log_case` are used by commands in later phases
/// (Phase 2–5). They will be referenced when those command modules land.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use tracing::error;

// ─── Action code constants ────────────────────────────────────────────────────

pub const LOGIN_SUCCESS: &str = "LOGIN_SUCCESS";
pub const LOGIN_FAILED: &str = "LOGIN_FAILED";
pub const LOGOUT: &str = "LOGOUT";
pub const PASSWORD_CHANGED: &str = "PASSWORD_CHANGED";
#[allow(dead_code)]
pub const MFA_ENABLED: &str = "MFA_ENABLED";
pub const MFA_DISABLED: &str = "MFA_DISABLED";
pub const MFA_RECOVERY_USED: &str = "MFA_RECOVERY_USED";
pub const MFA_VERIFIED: &str = "MFA_VERIFIED";
pub const API_TOKEN_CREATED: &str = "API_TOKEN_CREATED";
pub const API_TOKEN_REVOKED: &str = "API_TOKEN_REVOKED";
pub const SETUP_ACCOUNT: &str = "SETUP_ACCOUNT";
#[allow(dead_code)]
pub const SESSION_EXPIRED: &str = "SESSION_EXPIRED";
#[allow(dead_code)]
pub const SETTINGS_CHANGED: &str = "SETTINGS_CHANGED";
pub const MFA_ENROLLED: &str = "MFA_ENROLLED";

// ─── Case action codes ────────────────────────────────────────────────────────
pub const CASE_CREATED: &str = "CASE_CREATED";
pub const CASE_UPDATED: &str = "CASE_UPDATED";
pub const CASE_DELETED: &str = "CASE_DELETED";

// ─── Path helpers ─────────────────────────────────────────────────────────────

fn audit_dir() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.data_dir().join("DFARS").join("admin").join("audit"))
        .unwrap_or_else(|| PathBuf::from("audit"))
}

fn auth_audit_path() -> PathBuf {
    audit_dir().join("auth_audit.txt")
}

#[allow(dead_code)]
fn case_audit_path(case_id: &str) -> PathBuf {
    audit_dir().join("cases").join(format!("{case_id}_audit.txt"))
}

// ─── Write helpers ────────────────────────────────────────────────────────────

fn file_header(name: &str) -> String {
    let ts = chrono::Utc::now().to_rfc3339();
    format!(
        "{sep}\n  DFARS DESKTOP AUDIT LOG — {name}\n  Created: {ts}\n  WARNING: This file is protected. Do not modify or delete.\n  Format: TIMESTAMP | USER | ACTION | DETAILS\n{sep}\n\n",
        sep = "=".repeat(80),
    )
}

fn format_line(user: &str, action: &str, details: &str) -> String {
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6f").to_string();
    let safe_user = if user.is_empty() { "SYSTEM" } else { user };
    format!("{ts} | {safe_user} | {action} | {details}\n")
}

fn append_line(path: &std::path::Path, line: &str) {
    let first_write = !path.exists();

    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            error!("audit: could not create directory {}: {e}", parent.display());
            return;
        }
    }

    let result = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        if first_write {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("audit");
            f.write_all(file_header(stem).as_bytes())?;
        }
        f.write_all(line.as_bytes())?;
        f.flush()?;
        Ok(())
    })();

    if let Err(e) = result {
        error!("audit write failed for {}: {e}", path.display());
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Log an authentication event to `auth_audit.txt`.
pub fn log_auth(user: &str, action: &str, details: &str) {
    let line = format_line(user, action, details);
    append_line(auth_audit_path().as_path(), &line);
}

/// Log a case-scoped event to `cases/<case_id>_audit.txt`.
/// Used by case/evidence/custody commands.
pub fn log_case(case_id: &str, user: &str, action: &str, details: &str) {
    let line = format_line(user, action, details);
    append_line(case_audit_path(case_id).as_path(), &line);
}
