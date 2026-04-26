//! dfars-verify — standalone CLI for verifying DFARS audit bundles.
//!
//! Usage:
//!   dfars-verify <audit-bundle.json>
//!
//! Reads an exported audit bundle (from the `audit_export_case` Tauri command)
//! and verifies:
//!   1. Every entry's SHA-256 recomputes correctly.
//!   2. Every prev_hash links to the preceding entry's entry_hash.
//!   3. The bundle_hash matches the canonical JSON of entries.
//!
//! Exit codes:
//!   0 — verification passed
//!   1 — verification failed (tampered or malformed)
//!   2 — I/O or parse error

use std::{env, fs, process};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Re-export of the audit entry struct shape (must match dfars_desktop_lib).
#[derive(Debug, Serialize, Deserialize)]
struct AuditEntry {
    entry_id: i64,
    case_id: Option<String>,
    timestamp: String,
    actor: String,
    action: String,
    details: Option<String>,
    prev_hash: String,
    entry_hash: String,
}

#[derive(Debug, Deserialize)]
struct AuditExport {
    case_id: String,
    exported_at: String,
    entry_count: usize,
    entries: Vec<AuditEntry>,
    bundle_hash: String,
}

fn compute_entry_hash(
    prev_hash: &str,
    timestamp: &str,
    actor: &str,
    action: &str,
    details: Option<&str>,
) -> String {
    let payload = match details {
        Some(d) => format!("{prev_hash}:{timestamp}:{actor}:{action}:{d}"),
        None => format!("{prev_hash}:{timestamp}:{actor}:{action}:"),
    };
    let hash = Sha256::digest(payload.as_bytes());
    data_encoding::HEXLOWER.encode(&hash)
}

fn verify(export: &AuditExport) -> Result<(), String> {
    // 1. Verify entry count matches actual entries
    if export.entry_count != export.entries.len() {
        return Err(format!(
            "entry_count mismatch: claimed {} but found {} entries",
            export.entry_count,
            export.entries.len()
        ));
    }

    // 2. Verify hash chain links
    for window in export.entries.windows(2) {
        let prev = &window[0];
        let curr = &window[1];
        if curr.prev_hash != prev.entry_hash {
            return Err(format!(
                "chain break at entry_id {}: prev_hash ({}) != previous entry_hash ({})",
                curr.entry_id, curr.prev_hash, prev.entry_hash
            ));
        }
    }

    // 3. Verify each entry's hash
    for entry in &export.entries {
        let recomputed = compute_entry_hash(
            &entry.prev_hash,
            &entry.timestamp,
            &entry.actor,
            &entry.action,
            entry.details.as_deref(),
        );
        if recomputed != entry.entry_hash {
            return Err(format!(
                "hash mismatch at entry_id {}: stored={} recomputed={}",
                entry.entry_id, entry.entry_hash, recomputed
            ));
        }
    }

    // 4. Verify bundle hash
    let canonical = serde_json::to_string(&export.entries)
        .map_err(|e| format!("failed to canonicalize entries: {e}"))?;
    let bundle_recomputed = {
        let hash = Sha256::digest(canonical.as_bytes());
        data_encoding::HEXLOWER.encode(&hash)
    };
    if bundle_recomputed != export.bundle_hash {
        return Err(format!(
            "bundle_hash mismatch: stored={} recomputed={}",
            export.bundle_hash, bundle_recomputed
        ));
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: dfars-verify <audit-bundle.json>");
        process::exit(2);
    }

    let path = &args[1];
    let raw = match fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            process::exit(2);
        }
    };

    let export: AuditExport = match serde_json::from_str(&raw) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error parsing audit bundle: {e}");
            process::exit(2);
        }
    };

    println!("DFARS Audit Bundle Verification");
    println!("  Case:      {}", export.case_id);
    println!("  Exported:  {}", export.exported_at);
    println!("  Entries:   {}", export.entry_count);
    println!();

    match verify(&export) {
        Ok(()) => {
            println!("Result: VERIFIED — chain intact, all hashes match.");
            process::exit(0);
        }
        Err(msg) => {
            println!("Result: FAILED — {msg}");
            process::exit(1);
        }
    }
}
