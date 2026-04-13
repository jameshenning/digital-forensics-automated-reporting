-- DFARS Desktop Database Schema
-- Based on SWGDE/NIST standards for digital evidence management

PRAGMA foreign_keys = ON;

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    description TEXT,
    investigator TEXT NOT NULL,
    agency TEXT,
    start_date DATE NOT NULL,
    end_date DATE,
    status TEXT DEFAULT 'Active',
    priority TEXT DEFAULT 'Medium',
    classification TEXT,
    evidence_drive_path TEXT,           -- external drive root for evidence files (e.g. "E:\")
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Evidence table
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    description TEXT NOT NULL,
    collected_by TEXT NOT NULL,
    collection_datetime TIMESTAMP NOT NULL,
    location TEXT,
    status TEXT DEFAULT 'Collected',
    evidence_type TEXT,
    make_model TEXT,
    serial_number TEXT,
    storage_location TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

-- Hash verification table
CREATE TABLE IF NOT EXISTS hash_verification (
    hash_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    verified_by TEXT NOT NULL,
    verification_datetime TIMESTAMP NOT NULL,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

-- Chain of custody table
CREATE TABLE IF NOT EXISTS chain_of_custody (
    custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    custody_sequence INTEGER NOT NULL,
    action TEXT NOT NULL,
    from_party TEXT NOT NULL,
    to_party TEXT NOT NULL,
    location TEXT,
    custody_datetime TIMESTAMP NOT NULL,
    purpose TEXT,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

-- Tool usage table
CREATE TABLE IF NOT EXISTS tool_usage (
    tool_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    version TEXT,
    purpose TEXT NOT NULL,
    command_used TEXT,
    input_file TEXT,
    output_file TEXT,
    execution_datetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operator TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

-- Analysis notes table
CREATE TABLE IF NOT EXISTS analysis_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    category TEXT NOT NULL,
    finding TEXT NOT NULL,
    description TEXT,
    confidence_level TEXT DEFAULT 'Medium',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

-- Case tags table
CREATE TABLE IF NOT EXISTS case_tags (
    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    UNIQUE(case_id, tag)
);

-- Report templates table (content populated in Python to avoid SQL/Jinja escaping issues)
CREATE TABLE IF NOT EXISTS report_templates (
    template_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    template_content TEXT NOT NULL,
    format_type TEXT DEFAULT 'markdown',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_hash_evidence_id ON hash_verification(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence_id ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_tool_case_id ON tool_usage(case_id);
CREATE INDEX IF NOT EXISTS idx_analysis_case_id ON analysis_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_tags_case_id ON case_tags(case_id);

-- ─── Link analysis: entities, links, events ───────────────────
-- Additive tables powering the Link Analysis / Crime Line feature.
-- Entities are investigator-curated annotations (people, businesses,
-- phones, emails, aliases, etc.); links are generic relationships
-- between entities or evidence; case_events are investigator-authored
-- timeline entries that complement the system-generated timestamps
-- on evidence, custody, hash, tool, and analysis records.
--
-- All three tables are soft-delete only (is_deleted = 1) so edits
-- leave an auditable trail.

CREATE TABLE IF NOT EXISTS entities (
    entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,        -- person | business | phone | email | alias | address | account | vehicle
    display_name TEXT NOT NULL,
    subtype TEXT,                     -- person role: suspect | victim | witness | investigator | poi | other
    organizational_rank TEXT,         -- free-text title ("Boss", "Lieutenant"); NULL for non-person
    parent_entity_id INTEGER,         -- self-ref for org hierarchy
    notes TEXT,
    metadata_json TEXT,               -- type-specific extras
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_entity_id) REFERENCES entities (entity_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id);
CREATE INDEX IF NOT EXISTS idx_entities_case_type ON entities(case_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_parent ON entities(parent_entity_id);

CREATE TABLE IF NOT EXISTS entity_links (
    link_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    source_type TEXT NOT NULL,        -- 'entity' or 'evidence'
    source_id TEXT NOT NULL,          -- entity_id or evidence_id stored as TEXT
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    link_label TEXT,                  -- "owns", "employs", "called", "collected", "uses"
    directional INTEGER DEFAULT 1,    -- 0 = undirected
    weight REAL DEFAULT 1.0,
    notes TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_links_case ON entity_links(case_id);
CREATE INDEX IF NOT EXISTS idx_links_source ON entity_links(case_id, source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_links_target ON entity_links(case_id, target_type, target_id);

CREATE TABLE IF NOT EXISTS case_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    event_datetime TIMESTAMP NOT NULL,
    event_end_datetime TIMESTAMP,     -- NULL = point event
    category TEXT,                    -- observation | communication | movement | custodial | other
    related_entity_id INTEGER,
    related_evidence_id TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (related_entity_id) REFERENCES entities (entity_id) ON DELETE SET NULL,
    FOREIGN KEY (related_evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_events_case_dt ON case_events(case_id, event_datetime);

-- ─── Evidence file attachments + AI analyses (added 2026-04-11) ──
-- Per-evidence file uploads (digital artifacts collected as part of an
-- item) plus the AI-generated forensic / OSINT analysis reports that
-- synthesize the file metadata + investigator narrative into a single
-- structured report. Files can be soft-deleted; analyses are kept as
-- a history (each "Run Analysis" appends a new row).

CREATE TABLE IF NOT EXISTS evidence_files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,            -- absolute path under %APPDATA%\DFARS\evidence_files\
    sha256 TEXT NOT NULL,                 -- hex digest of the stored file
    size_bytes INTEGER NOT NULL,
    mime_type TEXT,
    metadata_json TEXT,                   -- locally extracted EXIF / PDF / etc.
    is_deleted INTEGER DEFAULT 0,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_evidence_files_eid ON evidence_files(evidence_id);

CREATE TABLE IF NOT EXISTS evidence_analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    osint_narrative TEXT,                 -- investigator-provided OSINT input text
    files_snapshot_json TEXT,             -- list of file_ids analyzed at the time
    report_markdown TEXT,                 -- AI-generated narrative
    tools_used TEXT,                      -- comma-separated tools (from AI)
    platforms_used TEXT,                  -- comma-separated OSINT platforms (from AI)
    status TEXT DEFAULT 'completed',      -- pending | completed | failed
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_evidence_analyses_eid ON evidence_analyses(evidence_id, created_at);

-- ─── Shares & Prints tracking (added 2026-04-12) ──────────────
-- Every time a record is emailed or exported/printed as .md, a row
-- is created here with the SHA-256 hash of the generated file, who
-- did it, when, and a mandatory narrative explaining why.

CREATE TABLE IF NOT EXISTS case_shares (
    share_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    record_type TEXT NOT NULL,        -- evidence | hash | custody | tool | analysis
    record_id TEXT NOT NULL,          -- the PK of the shared record
    record_summary TEXT,              -- human-readable one-liner of what was shared
    action TEXT NOT NULL,             -- email | print
    recipient TEXT,                   -- email address (for email action)
    file_path TEXT,                   -- where the .md was saved on disk
    file_hash TEXT NOT NULL,          -- SHA-256 of the generated .md
    narrative TEXT NOT NULL,          -- user-entered reason for sharing
    shared_by TEXT NOT NULL,          -- username
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_shares_case ON case_shares(case_id, created_at);
