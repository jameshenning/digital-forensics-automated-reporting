-- DFARS v3.0 Forensics Schema (PostgreSQL)
-- Consolidated migration from SQLite forensics/0001..0008

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
    evidence_drive_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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

CREATE TABLE IF NOT EXISTS hash_verification (
    hash_id SERIAL PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    verified_by TEXT NOT NULL,
    verification_datetime TIMESTAMP NOT NULL,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    custody_id SERIAL PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS tool_usage (
    tool_id SERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    tool_name TEXT NOT NULL,
    version TEXT,
    purpose TEXT NOT NULL,
    command_used TEXT,
    input_file TEXT,
    output_file TEXT,
    execution_datetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operator TEXT NOT NULL,
    input_sha256 TEXT,
    output_sha256 TEXT,
    environment_notes TEXT,
    reproduction_notes TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS analysis_notes (
    note_id SERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    category TEXT NOT NULL,
    finding TEXT NOT NULL,
    description TEXT,
    confidence_level TEXT DEFAULT 'Medium',
    created_by TEXT,
    method_reference TEXT,
    alternatives_considered TEXT,
    tool_version TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS analysis_reviews (
    review_id SERIAL PRIMARY KEY,
    note_id INTEGER NOT NULL REFERENCES analysis_notes(note_id) ON DELETE RESTRICT,
    reviewed_by TEXT NOT NULL,
    reviewed_at TIMESTAMP NOT NULL,
    review_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_tags (
    tag_id SERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    UNIQUE(case_id, tag)
);

CREATE TABLE IF NOT EXISTS report_templates (
    template_id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    template_content TEXT NOT NULL,
    format_type TEXT DEFAULT 'markdown',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entities (
    entity_id SERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    subtype TEXT,
    organizational_rank TEXT,
    parent_entity_id INTEGER,
    notes TEXT,
    metadata_json TEXT,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    photo_path TEXT,
    email TEXT,
    phone TEXT,
    username TEXT,
    employer TEXT,
    dob TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_entity_id) REFERENCES entities (entity_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS person_identifiers (
    identifier_id SERIAL PRIMARY KEY,
    entity_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    platform TEXT,
    notes TEXT,
    discovered_via_tool TEXT,
    attributed_by TEXT,
    attribution_basis TEXT,
    confidence_level TEXT,
    verification_status TEXT,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS business_identifiers (
    identifier_id SERIAL PRIMARY KEY,
    entity_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    platform TEXT,
    notes TEXT,
    discovered_via_tool TEXT,
    attributed_by TEXT,
    attribution_basis TEXT,
    confidence_level TEXT,
    verification_status TEXT,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS entity_links (
    link_id SERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    link_label TEXT,
    directional INTEGER DEFAULT 1,
    weight REAL DEFAULT 1.0,
    notes TEXT,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attributed_by TEXT,
    basis TEXT,
    confidence_level TEXT,
    method_reference TEXT,
    alternatives_considered TEXT,
    evidence_refs TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS case_events (
    event_id SERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    event_datetime TIMESTAMP NOT NULL,
    event_end_datetime TIMESTAMP,
    category TEXT,
    related_entity_id INTEGER,
    related_evidence_id TEXT,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (related_entity_id) REFERENCES entities (entity_id) ON DELETE SET NULL,
    FOREIGN KEY (related_evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence_files (
    file_id SERIAL PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    mime_type TEXT,
    metadata_json TEXT,
    is_deleted BOOLEAN DEFAULT FALSE,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS evidence_analyses (
    analysis_id SERIAL PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    osint_narrative TEXT,
    files_snapshot_json TEXT,
    report_markdown TEXT,
    tools_used TEXT,
    platforms_used TEXT,
    status TEXT DEFAULT 'completed',
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS case_shares (
    share_id SERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_id TEXT NOT NULL,
    record_summary TEXT,
    action TEXT NOT NULL,
    recipient TEXT,
    file_path TEXT,
    file_hash TEXT NOT NULL,
    narrative TEXT NOT NULL,
    shared_by TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_hash_evidence_id ON hash_verification(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence_id ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_tool_case_id ON tool_usage(case_id);
CREATE INDEX IF NOT EXISTS idx_tool_evidence_id ON tool_usage(evidence_id);
CREATE INDEX IF NOT EXISTS idx_analysis_case_id ON analysis_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_tags_case_id ON case_tags(case_id);
CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id);
CREATE INDEX IF NOT EXISTS idx_entities_case_type ON entities(case_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_parent ON entities(parent_entity_id);
CREATE INDEX IF NOT EXISTS idx_links_case ON entity_links(case_id);
CREATE INDEX IF NOT EXISTS idx_links_source ON entity_links(case_id, source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_links_target ON entity_links(case_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_events_case_dt ON case_events(case_id, event_datetime);
CREATE INDEX IF NOT EXISTS idx_evidence_files_eid ON evidence_files(evidence_id);
CREATE INDEX IF NOT EXISTS idx_evidence_analyses_eid ON evidence_analyses(evidence_id, created_at);
CREATE INDEX IF NOT EXISTS idx_shares_case ON case_shares(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_person_identifiers_entity ON person_identifiers(entity_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_person_identifiers_kind ON person_identifiers(entity_id, kind, is_deleted);
CREATE INDEX IF NOT EXISTS idx_person_identifiers_discovered_via_tool ON person_identifiers(discovered_via_tool);
CREATE INDEX IF NOT EXISTS idx_business_identifiers_entity ON business_identifiers(entity_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_business_identifiers_kind ON business_identifiers(entity_id, kind, is_deleted);
CREATE INDEX IF NOT EXISTS idx_business_identifiers_discovered_via_tool ON business_identifiers(discovered_via_tool);
