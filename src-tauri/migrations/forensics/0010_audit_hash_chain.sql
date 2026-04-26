-- migration 0010: hash-chained audit log
--
-- Replaces the flat-file-only audit trail with a cryptographically
-- verifiable hash chain stored in SQLite. Each entry's SHA-256
-- incorporates the previous entry's hash, producing a Merkle-style
-- tamper-evident sequence.
--
-- The flat-file audit (auth_audit.txt, <case>_audit.txt) continues
-- to be written for redundancy and human readability; this table
-- is the authoritative chain for verification.
--
-- Fields:
--   entry_id    — auto-increment primary key (ordering, not part of hash)
--   case_id     — nullable; NULL for auth/global events
--   timestamp   — ISO-8601 with microseconds (NTP-synced when possible)
--   actor       — "user:<username>" or "api_token:<name>"
--   action      — audit constant (e.g., CASE_CREATED, EVIDENCE_ADDED)
--   details     — free-text detail (length-capped by callers)
--   prev_hash   — hex SHA-256 of the previous entry; "GENESIS" for first
--   entry_hash  — hex SHA-256 of: prev_hash || timestamp || actor || action || details

CREATE TABLE IF NOT EXISTS audit_entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_case_id ON audit_entries(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action);
