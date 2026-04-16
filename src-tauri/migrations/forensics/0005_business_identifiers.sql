-- migration 0005: business_identifiers
-- Multi-valued OSINT-relevant identifiers for business entities.
-- Mirrors person_identifiers (migration 0004) with a business-specific kind allowlist.
-- Kind allowlist: domain | registration | ein | email | phone | address | social | url

CREATE TABLE IF NOT EXISTS business_identifiers (
    identifier_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    platform TEXT,
    notes TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_business_identifiers_entity
    ON business_identifiers(entity_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_business_identifiers_kind
    ON business_identifiers(entity_id, kind, is_deleted);
