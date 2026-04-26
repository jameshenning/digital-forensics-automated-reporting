/// Phase B (migration 0008) — Attribution Principles Integration Tests
///
/// Phase B applies the cross-examination methodology pattern from Phase A
/// (analysis_notes validation fields + analysis_reviews) to the *attribution*
/// surface: every assertion that "X is connected to Y" or "this email belongs
/// to person Z" now carries the basis of the attribution, who made the call,
/// and what level of confidence/verification supports it.
///
/// This file covers the load-bearing behaviors:
///   1. entity_links roundtrip with full attribution
///   2. entity_links v1-compat (NULL attribution stays NULL)
///   3. entity_links confidence_level allowlist enforcement
///   4. entity_links char-counted caps (Unicode-safe, mirrors Phase A)
///   5. person_identifiers roundtrip with full attribution
///   6. person_identifiers verification_status allowlist enforcement
///   7. business_identifiers roundtrip with full attribution
///   8. OSINT auto-discovery populates structured attribution defaults
///
/// Run: `cargo test --test phase_b_attribution_principles_integration`

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::NaiveDate;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

use dfars_desktop_lib::{
    db::{
        business_identifiers::{
            BusinessIdentifierInput, add_identifier as biz_add_identifier,
            insert_discovered_batch as biz_insert_discovered_batch,
            list_for_entity as biz_list_for_entity,
        },
        cases::{CaseInput, create_case},
        entities::{EntityInput, add_entity},
        links::{LinkInput, add_link, get_link, list_for_case as link_list_for_case},
        person_identifiers::{
            PersonIdentifierInput, add_identifier as person_add_identifier,
            insert_discovered_batch as person_insert_discovered_batch,
            list_for_entity as person_list_for_entity,
        },
    },
    error::AppError,
};

// ─── Test infrastructure ────────────────────────────────────────────────────

static DB_COUNTER: AtomicU64 = AtomicU64::new(8000);

/// Forensics schema with all migrations applied (1–8). Mirrors the schema
/// used by phase4_link_analysis_integration.rs but kept independent — each
/// test file embeds its own schema by project convention.
const FORENSICS_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    description TEXT,
    investigator TEXT NOT NULL,
    agency TEXT,
    start_date DATE NOT NULL,
    end_date DATE,
    status TEXT DEFAULT 'open',
    priority TEXT DEFAULT 'medium',
    classification TEXT,
    evidence_drive_path TEXT,
    metadata_json TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_tags (
    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    UNIQUE(case_id, tag),
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    description TEXT NOT NULL,
    collected_by TEXT NOT NULL,
    collection_datetime TIMESTAMP NOT NULL,
    location TEXT,
    status TEXT DEFAULT 'collected',
    evidence_type TEXT,
    metadata_json TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

-- migration 0010: hash-chained audit log
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

CREATE TABLE IF NOT EXISTS entities (
    entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    subtype TEXT,
    organizational_rank TEXT,
    parent_entity_id INTEGER,
    notes TEXT,
    metadata_json TEXT,
    photo_path TEXT,
    email TEXT,
    phone TEXT,
    username TEXT,
    employer TEXT,
    dob TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

-- entity_links + migration 0008 attribution columns
CREATE TABLE IF NOT EXISTS entity_links (
    link_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    link_label TEXT,
    directional INTEGER DEFAULT 1,
    weight REAL DEFAULT 1.0,
    notes TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attributed_by TEXT,
    basis TEXT,
    confidence_level TEXT,
    method_reference TEXT,
    alternatives_considered TEXT,
    evidence_refs TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

-- person_identifiers + migration 0008 attribution columns
CREATE TABLE IF NOT EXISTS person_identifiers (
    identifier_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

-- business_identifiers + migration 0008 attribution columns
CREATE TABLE IF NOT EXISTS business_identifiers (
    identifier_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);
"#;

async fn make_pool() -> SqlitePool {
    let _ = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("pool open");
    sqlx::raw_sql(FORENSICS_SCHEMA)
        .execute(&pool)
        .await
        .expect("schema apply");
    pool
}

async fn seed_case(pool: &SqlitePool, id: &str) -> String {
    let input = CaseInput {
        case_id: id.to_string(),
        case_name: format!("Test Case {id}"),
        description: None,
        investigator: "Alice".into(),
        agency: None,
        start_date: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
        end_date: None,
        status: None,
        priority: None,
        classification: None,
        evidence_drive_path: None,
        tags: vec![],
    };
    create_case(pool, &input).await.expect("create_case").case.case_id
}

async fn seed_person(pool: &SqlitePool, case_id: &str, name: &str) -> i64 {
    let input = EntityInput {
        entity_type: "person".into(),
        display_name: name.into(),
        subtype: Some("suspect".into()),
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
        email: None,
        phone: None,
        username: None,
        employer: None,
        dob: None,
    };
    add_entity(pool, case_id, &input).await.expect("add person").entity_id
}

async fn seed_business(pool: &SqlitePool, case_id: &str, name: &str) -> i64 {
    let input = EntityInput {
        entity_type: "business".into(),
        display_name: name.into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
        email: None,
        phone: None,
        username: None,
        employer: None,
        dob: None,
    };
    add_entity(pool, case_id, &input).await.expect("add business").entity_id
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn link_carries_full_attribution_roundtrip() {
    // INSERT a link with every Phase B attribution field populated, then
    // read it back via list + get and assert each field round-trips exactly.
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-LINK-001").await;
    let alice = seed_person(&pool, &case_id, "Alice").await;
    let acme = seed_business(&pool, &case_id, "Acme Corp").await;

    let input = LinkInput {
        source_type: "entity".into(),
        source_id: alice.to_string(),
        target_type: "entity".into(),
        target_id: acme.to_string(),
        link_label: Some("employs".into()),
        directional: Some(1),
        weight: Some(1.0),
        notes: Some("Inferred from intake interview".into()),
        attributed_by: Some("J. Smith".into()),
        basis: Some("Subject named target as employer in interview 2026-04-10".into()),
        confidence_level: Some("Medium".into()),
        method_reference: Some("Internal SOP-FRA-007".into()),
        alternatives_considered: Some("Could be former employer; not yet corroborated".into()),
        evidence_refs: Some("E-001, E-007".into()),
    };
    let added = add_link(&pool, &case_id, &input).await.expect("add link");

    // Round-trip via list_for_case.
    let list = link_list_for_case(&pool, &case_id).await.expect("list");
    assert_eq!(list.len(), 1);
    let l = &list[0];
    assert_eq!(l.attributed_by.as_deref(), Some("J. Smith"));
    assert_eq!(
        l.basis.as_deref(),
        Some("Subject named target as employer in interview 2026-04-10")
    );
    assert_eq!(l.confidence_level.as_deref(), Some("Medium"));
    assert_eq!(l.method_reference.as_deref(), Some("Internal SOP-FRA-007"));
    assert_eq!(
        l.alternatives_considered.as_deref(),
        Some("Could be former employer; not yet corroborated")
    );
    assert_eq!(l.evidence_refs.as_deref(), Some("E-001, E-007"));

    // Round-trip via get_link.
    let g = get_link(&pool, added.link_id).await.expect("get link");
    assert_eq!(g.attributed_by.as_deref(), Some("J. Smith"));
    assert_eq!(g.confidence_level.as_deref(), Some("Medium"));
}

#[tokio::test]
async fn link_v1_compat_keeps_attribution_null() {
    // Insert a minimal link with no attribution fields populated. The Read
    // struct must come back with all attribution fields = None — we never
    // silently default them.
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-LINK-V1").await;
    let alice = seed_person(&pool, &case_id, "Alice").await;
    let bob = seed_person(&pool, &case_id, "Bob").await;

    let input = LinkInput {
        source_type: "entity".into(),
        source_id: alice.to_string(),
        target_type: "entity".into(),
        target_id: bob.to_string(),
        link_label: Some("knows".into()),
        directional: None,
        weight: None,
        notes: None,
        attributed_by: None,
        basis: None,
        confidence_level: None,
        method_reference: None,
        alternatives_considered: None,
        evidence_refs: None,
    };
    let added = add_link(&pool, &case_id, &input).await.expect("add");

    let g = get_link(&pool, added.link_id).await.expect("get");
    assert!(g.attributed_by.is_none());
    assert!(g.basis.is_none());
    assert!(g.confidence_level.is_none());
    assert!(g.method_reference.is_none());
    assert!(g.alternatives_considered.is_none());
    assert!(g.evidence_refs.is_none());
}

#[tokio::test]
async fn link_invalid_confidence_level_rejected() {
    // confidence_level enforces an allowlist (Low | Medium | High).
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-LINK-CONF").await;
    let alice = seed_person(&pool, &case_id, "Alice").await;
    let bob = seed_person(&pool, &case_id, "Bob").await;

    let input = LinkInput {
        source_type: "entity".into(),
        source_id: alice.to_string(),
        target_type: "entity".into(),
        target_id: bob.to_string(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
        attributed_by: None,
        basis: None,
        confidence_level: Some("Bogus".into()),
        method_reference: None,
        alternatives_considered: None,
        evidence_refs: None,
    };
    let err = add_link(&pool, &case_id, &input).await.unwrap_err();
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "confidence_level"),
        "expected ValidationError on confidence_level, got {err:?}"
    );
}

#[tokio::test]
async fn link_basis_char_cap_counts_chars_not_bytes() {
    // basis cap is 5000 *characters*, not bytes — same Unicode pattern as
    // Phase A. A 5000-emoji string (~20 KB of bytes) must PASS; 5001 fails.
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-LINK-LEN").await;
    let alice = seed_person(&pool, &case_id, "Alice").await;
    let bob = seed_person(&pool, &case_id, "Bob").await;

    let emoji_5000 = "🦀".repeat(5000);
    assert_eq!(emoji_5000.chars().count(), 5000);
    let mut input = LinkInput {
        source_type: "entity".into(),
        source_id: alice.to_string(),
        target_type: "entity".into(),
        target_id: bob.to_string(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
        attributed_by: None,
        basis: Some(emoji_5000),
        confidence_level: None,
        method_reference: None,
        alternatives_considered: None,
        evidence_refs: None,
    };
    add_link(&pool, &case_id, &input)
        .await
        .expect("5000-char Unicode basis must be accepted");

    // 5001 fails.
    input.basis = Some("🦀".repeat(5001));
    let err = add_link(&pool, &case_id, &input).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "basis"));
}

#[tokio::test]
async fn person_identifier_attribution_roundtrip() {
    // INSERT a person identifier with full attribution; read back via list.
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-PID-001").await;
    let alice = seed_person(&pool, &case_id, "Alice").await;

    let input = PersonIdentifierInput {
        kind: "email".into(),
        value: "alice@protonmail.com".into(),
        platform: Some("protonmail".into()),
        notes: None,
        attributed_by: Some("J. Smith".into()),
        attribution_basis: Some("Self-reported in intake form 2026-04-10".into()),
        confidence_level: Some("High".into()),
        verification_status: Some("Confirmed".into()),
    };
    let added = person_add_identifier(&pool, alice, &input)
        .await
        .expect("add ident");
    assert_eq!(added.attributed_by.as_deref(), Some("J. Smith"));
    assert_eq!(added.confidence_level.as_deref(), Some("High"));
    assert_eq!(added.verification_status.as_deref(), Some("Confirmed"));

    let list = person_list_for_entity(&pool, alice).await.expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(
        list[0].attribution_basis.as_deref(),
        Some("Self-reported in intake form 2026-04-10")
    );
}

#[tokio::test]
async fn person_identifier_invalid_verification_rejected() {
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-PID-VER").await;
    let alice = seed_person(&pool, &case_id, "Alice").await;

    let input = PersonIdentifierInput {
        kind: "email".into(),
        value: "alice@example.com".into(),
        platform: None,
        notes: None,
        attributed_by: None,
        attribution_basis: None,
        confidence_level: None,
        verification_status: Some("Bogus".into()),
    };
    let err = person_add_identifier(&pool, alice, &input)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "verification_status"),
        "expected ValidationError on verification_status, got {err:?}"
    );
}

#[tokio::test]
async fn business_identifier_attribution_roundtrip() {
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-BID-001").await;
    let acme = seed_business(&pool, &case_id, "Acme Corp").await;

    let input = BusinessIdentifierInput {
        kind: "domain".into(),
        value: "acme.example".into(),
        platform: None,
        notes: None,
        attributed_by: Some("OSINT analyst".into()),
        attribution_basis: Some("whois lookup 2026-04-12".into()),
        confidence_level: Some("Medium".into()),
        verification_status: Some("Tentative".into()),
    };
    let added = biz_add_identifier(&pool, acme, &input)
        .await
        .expect("add biz ident");
    assert_eq!(added.attributed_by.as_deref(), Some("OSINT analyst"));
    assert_eq!(added.verification_status.as_deref(), Some("Tentative"));

    let list = biz_list_for_entity(&pool, acme).await.expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].confidence_level.as_deref(), Some("Medium"));
}

#[tokio::test]
async fn osint_auto_discovery_populates_structured_attribution() {
    // The Phase B contract: insert_discovered_batch populates the four
    // attribution columns on every row it inserts so auto-discovered
    // identifiers carry honest provenance from the moment they land.
    let pool = make_pool().await;
    let case_id = seed_case(&pool, "PHB-OSINT-001").await;
    let alice = seed_person(&pool, &case_id, "Alice").await;

    let batch = vec![(
        "email".to_string(),
        "discovered@example.com".to_string(),
        None,
        "theHarvester".to_string(),
    )];
    let (_, inserted) = person_insert_discovered_batch(&pool, alice, &batch, "2026-04-25", 50)
        .await
        .expect("batch insert");
    assert_eq!(inserted, 1);

    let list = person_list_for_entity(&pool, alice).await.expect("list");
    let row = list
        .iter()
        .find(|r| r.value == "discovered@example.com")
        .expect("inserted row");
    assert_eq!(row.discovered_via_tool.as_deref(), Some("theHarvester"));
    assert_eq!(row.attributed_by.as_deref(), Some("OSINT auto-discovery"));
    assert_eq!(
        row.attribution_basis.as_deref(),
        Some("Surfaced by theHarvester")
    );
    assert_eq!(row.confidence_level.as_deref(), Some("Low"));
    assert_eq!(row.verification_status.as_deref(), Some("Unverified"));
    // notes is no longer used as a free-text provenance stamp on new rows.
    assert!(row.notes.is_none());

    // Same shape for the business path.
    let acme = seed_business(&pool, &case_id, "Acme Corp").await;
    let biz_batch = vec![(
        "domain".to_string(),
        "acme.example".to_string(),
        None,
        "subfinder".to_string(),
    )];
    let (_, biz_inserted) =
        biz_insert_discovered_batch(&pool, acme, &biz_batch, "2026-04-25", 50)
            .await
            .expect("biz batch");
    assert_eq!(biz_inserted, 1);
    let biz_list = biz_list_for_entity(&pool, acme).await.expect("biz list");
    let biz_row = biz_list
        .iter()
        .find(|r| r.value == "acme.example")
        .expect("biz inserted");
    assert_eq!(biz_row.attributed_by.as_deref(), Some("OSINT auto-discovery"));
    assert_eq!(
        biz_row.attribution_basis.as_deref(),
        Some("Surfaced by subfinder")
    );
    assert_eq!(biz_row.confidence_level.as_deref(), Some("Low"));
    assert_eq!(biz_row.verification_status.as_deref(), Some("Unverified"));
}
