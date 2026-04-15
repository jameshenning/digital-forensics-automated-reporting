-- Person identifiers table.
--
-- A single person entity typically has many OSINT-relevant identifiers
-- across platforms (multiple emails, Twitter/Reddit/GitHub/Discord handles,
-- phone numbers, personal URLs). The existing `entities.email/phone/username`
-- columns (migration 0002) stay as the "primary" shortcut for display, but
-- the source of truth for OSINT submission is this table.
--
-- `kind` values: email | username | handle | phone | url
--   - `email`    — RFC-5322 mailbox
--   - `username` — login name on a specific platform
--   - `handle`   — display handle (Twitter @x, Reddit u/x, Discord name#1234)
--   - `phone`    — E.164 or free-form
--   - `url`      — personal/profile URL
--
-- `platform` is free-form and optional — lets the investigator record the
-- platform context (`twitter`, `reddit`, `github`, `linkedin`, `discord`,
-- `gmail`, etc.) so the OSINT submission flow can dispatch the right tool.
--
-- Soft-delete only (matches entities, entity_links, case_events). The FK to
-- entities is ON DELETE RESTRICT for the same reason as everywhere else in
-- the schema — forensic audit trails never hard-delete parent rows.

CREATE TABLE IF NOT EXISTS person_identifiers (
    identifier_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    kind TEXT NOT NULL,                       -- email | username | handle | phone | url
    value TEXT NOT NULL,
    platform TEXT,                            -- free-form: twitter, reddit, github, ...
    notes TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_person_identifiers_entity
    ON person_identifiers(entity_id, is_deleted);

CREATE INDEX IF NOT EXISTS idx_person_identifiers_kind
    ON person_identifiers(entity_id, kind, is_deleted);
