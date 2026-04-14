/// Phase 4 Link Analysis Integration Tests
///
/// Covers all 19 test families from the Phase 4 brief:
///   1.  Entity CRUD
///   2.  Entity type + subtype validation
///   3.  Entity parent validation (self-parent, cross-case, cycle)
///   4.  Entity metadata_json validation
///   5.  Entity soft-delete cascade to entity_links
///   6.  Link endpoint validation
///   7.  Link CRUD
///   8.  Event CRUD
///   9.  Event category allowlist
///  10.  Event datetime validation (future, end < start)
///  11.  Event related_entity_id + related_evidence_id FK check
///  12.  Graph assembly happy path
///  13.  Graph with entity_type filter
///  14.  Graph with include_evidence=false
///  15.  Graph excludes soft-deleted entities and links
///  16.  Crime line assembly (all 6 groups)
///  17.  Crime line date range filter
///  18.  Crime line excludes soft-deleted events; includes auto-derived rows
///  19.  Session guard negative tests
///
/// Run: `cargo test --test phase4_link_analysis_integration`

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use chrono::{Duration, NaiveDate, NaiveDateTime, Utc};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

use dfars_desktop_lib::{
    auth::{argon, lockout::LockoutMap, session::SessionState},
    crypto::CryptoState,
    db::{
        AppDb,
        analysis::{AnalysisInput, add_analysis},
        cases::{CaseInput, create_case},
        custody::{CustodyInput, add_custody},
        entities::{EntityInput, add_entity, get_entity, list_for_case as entity_list_for_case,
                   soft_delete as entity_soft_delete, update_entity},
        events::{EventInput, add_event, get_event, list_for_case as event_list_for_case,
                 soft_delete as event_soft_delete, update_event},
        evidence::{EvidenceInput, add_evidence},
        graph::{GraphFilter, TimelineFilter, build_crime_line, build_graph},
        hashes::{HashInput, add_hash},
        links::{LinkInput, add_link, list_for_case as link_list_for_case,
                soft_delete as link_soft_delete},
        tools::{ToolInput, add_tool},
    },
    error::AppError,
    state::AppState,
};

// ─── Test infrastructure ──────────────────────────────────────────────────────

/// Unique DB counter for test isolation (each test gets a fresh pool).
static DB_COUNTER: AtomicU64 = AtomicU64::new(4000);

/// Verbatim copy of the forensics schema (all tables through Phase 4).
/// Each integration test embeds its own copy per project convention.
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
    hash_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    verified_by TEXT NOT NULL,
    verification_datetime TIMESTAMP NOT NULL,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

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

CREATE TABLE IF NOT EXISTS tool_usage (
    tool_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

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

CREATE TABLE IF NOT EXISTS case_tags (
    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    UNIQUE(case_id, tag)
);

CREATE TABLE IF NOT EXISTS report_templates (
    template_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    template_content TEXT NOT NULL,
    format_type TEXT DEFAULT 'markdown',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_links_case ON entity_links(case_id);

CREATE TABLE IF NOT EXISTS case_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    event_datetime TIMESTAMP NOT NULL,
    event_end_datetime TIMESTAMP,
    category TEXT,
    related_entity_id INTEGER,
    related_evidence_id TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (related_entity_id) REFERENCES entities (entity_id) ON DELETE SET NULL,
    FOREIGN KEY (related_evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_events_case_dt ON case_events(case_id, event_datetime);

CREATE TABLE IF NOT EXISTS evidence_files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT,
    metadata_json TEXT,
    is_deleted INTEGER DEFAULT 0,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS evidence_analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    share_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
"#;

async fn new_forensics_pool() -> SqlitePool {
    let _n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);

    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("failed to open :memory: pool");

    sqlx::raw_sql(FORENSICS_SCHEMA)
        .execute(&pool)
        .await
        .expect("failed to apply forensics schema");

    pool
}

/// Build a minimal `AppState` backed by a fresh forensics pool.
/// Returns `(Arc<AppState>, forensics_pool)`.
async fn make_state() -> (Arc<AppState>, SqlitePool) {
    let forensics = new_forensics_pool().await;

    // Auth pool — minimal, not used for Phase 4 DB queries
    let auth_opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);
    let auth = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(auth_opts)
        .await
        .expect("auth pool failed");

    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_login_count INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMP,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT,
            mfa_enrolled_at TIMESTAMP
        );",
    )
    .execute(&auth)
    .await
    .expect("auth schema failed");

    let db = AppDb {
        forensics: forensics.clone(),
        auth,
    };

    let crypto = CryptoState::new_with_random_key();
    let dummy_hash = argon::make_dummy_hash();

    let state = Arc::new(AppState {
        db,
        crypto,
        lockout: LockoutMap::new(),
        sessions: SessionState::new(),
        dummy_hash,
    });

    (state, forensics)
}

/// Helper: create a test case, return case_id.
async fn make_case(pool: &SqlitePool, id: &str) -> String {
    let input = CaseInput {
        case_id: id.to_string(),
        case_name: format!("Test Case {id}"),
        description: None,
        investigator: "Alice".into(),
        agency: None,
        start_date: NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
        end_date: None,
        status: None,
        priority: None,
        classification: None,
        evidence_drive_path: None,
        tags: vec![],
    };
    create_case(pool, &input).await.expect("make_case failed").case.case_id
}

/// Helper: create a test entity, return entity_id.
async fn make_entity(pool: &SqlitePool, case_id: &str, name: &str, etype: &str) -> i64 {
    let input = EntityInput {
        entity_type: etype.to_string(),
        display_name: name.to_string(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
    };
    add_entity(pool, case_id, &input)
        .await
        .expect("make_entity failed")
        .entity_id
}

/// Helper: create a test evidence item, return evidence_id.
async fn make_evidence(pool: &SqlitePool, case_id: &str, eid: &str) -> String {
    let past = Utc::now().naive_utc() - Duration::hours(1);
    let input = EvidenceInput {
        evidence_id: eid.to_string(),
        description: format!("Evidence {eid}"),
        collected_by: "Alice".into(),
        collection_datetime: past,
        location: None,
        status: None,
        evidence_type: None,
        make_model: None,
        serial_number: None,
        storage_location: None,
    };
    add_evidence(pool, case_id, &input)
        .await
        .expect("make_evidence failed")
        .evidence_id
}

/// Helper: a past NaiveDateTime for event_datetime tests.
fn past_dt() -> NaiveDateTime {
    Utc::now().naive_utc() - Duration::hours(2)
}

// ─── Test 1: Entity CRUD ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_entity_crud() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "CRUD-01").await;

    // add
    let input = EntityInput {
        entity_type: "person".into(),
        display_name: "Alice Smith".into(),
        subtype: Some("suspect".into()),
        organizational_rank: Some("Boss".into()),
        parent_entity_id: None,
        notes: Some("Key suspect".into()),
        metadata_json: None,
    };
    let entity = add_entity(&pool, &case_id, &input).await.expect("add failed");
    assert_eq!(entity.display_name, "Alice Smith");
    assert_eq!(entity.entity_type, "person");
    assert_eq!(entity.subtype.as_deref(), Some("suspect"));
    assert_eq!(entity.is_deleted, 0);

    // list
    let list = entity_list_for_case(&pool, &case_id).await.expect("list failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].entity_id, entity.entity_id);

    // get
    let fetched = get_entity(&pool, entity.entity_id).await.expect("get failed");
    assert_eq!(fetched.entity_id, entity.entity_id);

    // update
    let update_input = EntityInput {
        entity_type: "person".into(),
        display_name: "Alice Jones".into(),
        subtype: Some("witness".into()),
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
    };
    let updated = update_entity(&pool, entity.entity_id, &update_input)
        .await
        .expect("update failed");
    assert_eq!(updated.display_name, "Alice Jones");
    assert_eq!(updated.subtype.as_deref(), Some("witness"));

    // soft_delete
    entity_soft_delete(&pool, entity.entity_id).await.expect("soft_delete failed");

    // list should be empty now
    let list2 = entity_list_for_case(&pool, &case_id).await.expect("list2 failed");
    assert!(list2.is_empty(), "deleted entity should not appear in list");
}

// ─── Test 2: Entity type + subtype validation ─────────────────────────────────

#[tokio::test]
async fn test_entity_type_subtype_validation() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "VAL-01").await;

    // Invalid entity_type
    let bad_type = EntityInput {
        entity_type: "spaceship".into(),
        display_name: "X".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
    };
    let err = add_entity(&pool, &case_id, &bad_type).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "invalid entity_type must be rejected: {err:?}");

    // Non-person with subtype → rejected
    let bad_subtype = EntityInput {
        entity_type: "business".into(),
        display_name: "Acme Corp".into(),
        subtype: Some("suspect".into()),
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
    };
    let err = add_entity(&pool, &case_id, &bad_subtype).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "non-person subtype must be rejected: {err:?}");

    // Person without subtype → allowed
    let ok = EntityInput {
        entity_type: "person".into(),
        display_name: "Bob".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
    };
    add_entity(&pool, &case_id, &ok).await.expect("person without subtype should be allowed");

    // Invalid subtype for person
    let bad_person_subtype = EntityInput {
        entity_type: "person".into(),
        display_name: "Carol".into(),
        subtype: Some("alien".into()),
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: None,
    };
    let err = add_entity(&pool, &case_id, &bad_person_subtype).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "invalid person subtype must be rejected: {err:?}");
}

// ─── Test 3: Entity parent validation ────────────────────────────────────────

#[tokio::test]
async fn test_entity_parent_validation() {
    let (_, pool) = make_state().await;
    let case_a = make_case(&pool, "PARENT-A").await;
    let case_b = make_case(&pool, "PARENT-B").await;

    let entity_a = make_entity(&pool, &case_a, "Alice", "person").await;

    // Self-parent on update
    let self_input = EntityInput {
        entity_type: "person".into(),
        display_name: "Alice Updated".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: Some(entity_a),
        notes: None,
        metadata_json: None,
    };
    let err = update_entity(&pool, entity_a, &self_input).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "self-parent must be rejected: {err:?}");

    // Parent in different case (entity_b is in case_b, trying to use as parent in case_a)
    let entity_b = make_entity(&pool, &case_b, "Bob", "person").await;
    let input_cross = EntityInput {
        entity_type: "person".into(),
        display_name: "Carol".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: Some(entity_b),
        notes: None,
        metadata_json: None,
    };
    let err = add_entity(&pool, &case_a, &input_cross).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "cross-case parent must be rejected: {err:?}");

    // Cycle: A → B → C → A
    // entity_a already exists in case_a. Create B with parent A, then C with parent B,
    // then try to update A's parent to C (which would create A→B→C→A).
    let entity_b_in_a = make_entity(&pool, &case_a, "Bob in A", "person").await;
    let input_b_parent = EntityInput {
        entity_type: "person".into(),
        display_name: "Bob with parent A".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: Some(entity_a),
        notes: None,
        metadata_json: None,
    };
    update_entity(&pool, entity_b_in_a, &input_b_parent)
        .await
        .expect("update B's parent to A must succeed");

    let input_c = EntityInput {
        entity_type: "person".into(),
        display_name: "Carol in A".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: Some(entity_b_in_a),
        notes: None,
        metadata_json: None,
    };
    let entity_c = add_entity(&pool, &case_a, &input_c)
        .await
        .expect("add C with parent B must succeed")
        .entity_id;

    // Now try to update A's parent to C — this creates A→B→C→A cycle.
    let cycle_input = EntityInput {
        entity_type: "person".into(),
        display_name: "Alice (cycle attempt)".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: Some(entity_c),
        notes: None,
        metadata_json: None,
    };
    let err = update_entity(&pool, entity_a, &cycle_input).await.unwrap_err();
    assert!(
        matches!(err, AppError::EntityCycle { .. }),
        "cycle A→B→C→A must be rejected with EntityCycle: {err:?}"
    );
}

// ─── Test 4: Entity metadata_json validation ──────────────────────────────────

#[tokio::test]
async fn test_entity_metadata_json_validation() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "JSON-01").await;

    // Invalid JSON → rejected
    let bad = EntityInput {
        entity_type: "person".into(),
        display_name: "Alice".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: Some("{not valid json}".into()),
    };
    let err = add_entity(&pool, &case_id, &bad).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "bad JSON must be rejected: {err:?}");

    // Valid JSON → accepted
    let good = EntityInput {
        entity_type: "person".into(),
        display_name: "Bob".into(),
        subtype: None,
        organizational_rank: None,
        parent_entity_id: None,
        notes: None,
        metadata_json: Some(r#"{"phone": "555-1234"}"#.into()),
    };
    add_entity(&pool, &case_id, &good).await.expect("valid JSON should be accepted");
}

// ─── Test 5: Entity soft-delete cascade to entity_links ──────────────────────

#[tokio::test]
async fn test_entity_soft_delete_cascades_to_links() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "CASCADE-01").await;

    let a = make_entity(&pool, &case_id, "Alice", "person").await;
    let b = make_entity(&pool, &case_id, "Bob", "person").await;

    // Create a link A → B
    let link_input = LinkInput {
        source_type: "entity".into(),
        source_id: a.to_string(),
        target_type: "entity".into(),
        target_id: b.to_string(),
        link_label: Some("knows".into()),
        directional: None,
        weight: None,
        notes: None,
    };
    let link = add_link(&pool, &case_id, &link_input).await.expect("add link failed");

    // Verify link is present
    let links_before = link_list_for_case(&pool, &case_id).await.expect("list links failed");
    assert_eq!(links_before.len(), 1, "link must be present before cascade");

    // Soft-delete entity A — must cascade to the link
    entity_soft_delete(&pool, a).await.expect("soft delete entity failed");

    // Link should now be invisible (is_deleted = 1)
    let links_after = link_list_for_case(&pool, &case_id).await.expect("list links after");
    assert!(
        links_after.is_empty(),
        "link should be soft-deleted when source entity is deleted, got {} links",
        links_after.len()
    );

    // Verify the link row still exists but is_deleted = 1 (not hard-deleted)
    let raw: (i64,) = sqlx::query_as(
        "SELECT is_deleted FROM entity_links WHERE link_id = ?",
    )
    .bind(link.link_id)
    .fetch_one(&pool)
    .await
    .expect("raw query for link row failed");
    assert_eq!(raw.0, 1, "link row must be soft-deleted (is_deleted=1), not hard-deleted");
}

// ─── Test 6: Link endpoint validation ────────────────────────────────────────

#[tokio::test]
async fn test_link_endpoint_validation() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "LINK-VAL-01").await;
    let a = make_entity(&pool, &case_id, "Alice", "person").await;
    let ev = make_evidence(&pool, &case_id, "EV-001").await;

    // Link from non-existent entity → LinkEndpointMissing
    let bad_entity = LinkInput {
        source_type: "entity".into(),
        source_id: "99999".into(),
        target_type: "entity".into(),
        target_id: a.to_string(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
    };
    let err = add_link(&pool, &case_id, &bad_entity).await.unwrap_err();
    assert!(
        matches!(err, AppError::LinkEndpointMissing { .. }),
        "missing entity endpoint must be LinkEndpointMissing: {err:?}"
    );

    // Link from valid entity to non-existent evidence → LinkEndpointMissing
    let bad_evidence = LinkInput {
        source_type: "entity".into(),
        source_id: a.to_string(),
        target_type: "evidence".into(),
        target_id: "EV-GHOST".into(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
    };
    let err = add_link(&pool, &case_id, &bad_evidence).await.unwrap_err();
    assert!(
        matches!(err, AppError::LinkEndpointMissing { .. }),
        "missing evidence endpoint must be LinkEndpointMissing: {err:?}"
    );

    // Self-loop → ValidationError
    let self_loop = LinkInput {
        source_type: "entity".into(),
        source_id: a.to_string(),
        target_type: "entity".into(),
        target_id: a.to_string(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
    };
    let err = add_link(&pool, &case_id, &self_loop).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "self-loop must be ValidationError: {err:?}");

    // Valid entity → evidence link
    let ok = LinkInput {
        source_type: "entity".into(),
        source_id: a.to_string(),
        target_type: "evidence".into(),
        target_id: ev.clone(),
        link_label: Some("collected".into()),
        directional: None,
        weight: None,
        notes: None,
    };
    add_link(&pool, &case_id, &ok).await.expect("valid entity→evidence link should succeed");
}

// ─── Test 7: Link CRUD ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_link_crud() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "LINK-CRUD-01").await;
    let a = make_entity(&pool, &case_id, "Alice", "person").await;
    let b = make_entity(&pool, &case_id, "Bob", "business").await;

    // add
    let input = LinkInput {
        source_type: "entity".into(),
        source_id: a.to_string(),
        target_type: "entity".into(),
        target_id: b.to_string(),
        link_label: Some("employs".into()),
        directional: Some(1),
        weight: Some(2.5),
        notes: None,
    };
    let link = add_link(&pool, &case_id, &input).await.expect("add link");
    assert_eq!(link.link_label.as_deref(), Some("employs"));
    assert!((link.weight - 2.5).abs() < f64::EPSILON);
    assert_eq!(link.directional, 1);

    // list
    let list = link_list_for_case(&pool, &case_id).await.expect("list links");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].link_id, link.link_id);

    // soft_delete
    link_soft_delete(&pool, link.link_id).await.expect("soft delete link");

    // list should be empty
    let list2 = link_list_for_case(&pool, &case_id).await.expect("list2 links");
    assert!(list2.is_empty(), "deleted link should not appear in list");
}

// ─── Test 8: Event CRUD ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_event_crud() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "EVT-CRUD-01").await;

    // add
    let input = EventInput {
        title: "Suspect seen at location".into(),
        description: Some("Detailed description".into()),
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: Some("observation".into()),
        related_entity_id: None,
        related_evidence_id: None,
    };
    let event = add_event(&pool, &case_id, &input).await.expect("add event");
    assert_eq!(event.title, "Suspect seen at location");
    assert_eq!(event.category.as_deref(), Some("observation"));
    assert_eq!(event.is_deleted, 0);

    // list
    let list = event_list_for_case(&pool, &case_id).await.expect("list events");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].event_id, event.event_id);

    // get
    let fetched = get_event(&pool, event.event_id).await.expect("get event");
    assert_eq!(fetched.event_id, event.event_id);

    // update
    let update_input = EventInput {
        title: "Suspect seen at different location".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: Some("movement".into()),
        related_entity_id: None,
        related_evidence_id: None,
    };
    let updated = update_event(&pool, event.event_id, &update_input).await.expect("update event");
    assert_eq!(updated.title, "Suspect seen at different location");
    assert_eq!(updated.category.as_deref(), Some("movement"));

    // soft_delete
    event_soft_delete(&pool, event.event_id).await.expect("soft delete event");

    // list should be empty
    let list2 = event_list_for_case(&pool, &case_id).await.expect("list2 events");
    assert!(list2.is_empty(), "deleted event should not appear in list");
}

// ─── Test 9: Event category allowlist ────────────────────────────────────────

#[tokio::test]
async fn test_event_category_allowlist() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "EVT-CAT-01").await;

    // Invalid category
    let bad = EventInput {
        title: "Test event".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: Some("explosion".into()),
        related_entity_id: None,
        related_evidence_id: None,
    };
    let err = add_event(&pool, &case_id, &bad).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "invalid category must be rejected: {err:?}");

    // None category → allowed
    let no_cat = EventInput {
        title: "No category event".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: None,
        related_entity_id: None,
        related_evidence_id: None,
    };
    add_event(&pool, &case_id, &no_cat).await.expect("None category must be allowed");

    // All valid categories must be accepted
    for cat in &["observation", "communication", "movement", "custodial", "other"] {
        let good = EventInput {
            title: format!("Event {cat}"),
            description: None,
            event_datetime: past_dt(),
            event_end_datetime: None,
            category: Some(cat.to_string()),
            related_entity_id: None,
            related_evidence_id: None,
        };
        add_event(&pool, &case_id, &good)
            .await
            .unwrap_or_else(|e| panic!("category '{cat}' must be valid: {e:?}"));
    }
}

// ─── Test 10: Event datetime validation ──────────────────────────────────────

#[tokio::test]
async fn test_event_datetime_validation() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "EVT-DT-01").await;

    // Future datetime → rejected
    let future_dt = Utc::now().naive_utc() + Duration::hours(1);
    let bad_future = EventInput {
        title: "Future event".into(),
        description: None,
        event_datetime: future_dt,
        event_end_datetime: None,
        category: None,
        related_entity_id: None,
        related_evidence_id: None,
    };
    let err = add_event(&pool, &case_id, &bad_future).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "future datetime must be rejected: {err:?}");

    // end < start → rejected
    let start = past_dt();
    let end_before_start = start - Duration::hours(1);
    let bad_end = EventInput {
        title: "End before start".into(),
        description: None,
        event_datetime: start,
        event_end_datetime: Some(end_before_start),
        category: None,
        related_entity_id: None,
        related_evidence_id: None,
    };
    let err = add_event(&pool, &case_id, &bad_end).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "end < start must be rejected: {err:?}");

    // Valid range event (end == start is also valid)
    let end_ok = start + Duration::hours(1);
    let good = EventInput {
        title: "Range event".into(),
        description: None,
        event_datetime: start,
        event_end_datetime: Some(end_ok),
        category: None,
        related_entity_id: None,
        related_evidence_id: None,
    };
    add_event(&pool, &case_id, &good).await.expect("valid range event must be accepted");
}

// ─── Test 11: Event related FK validation ────────────────────────────────────

#[tokio::test]
async fn test_event_related_fk_validation() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "EVT-FK-01").await;

    // Missing entity_id → ValidationError
    let bad_entity = EventInput {
        title: "Event".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: None,
        related_entity_id: Some(99999),
        related_evidence_id: None,
    };
    let err = add_event(&pool, &case_id, &bad_entity).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "missing entity FK must be rejected: {err:?}");

    // Missing evidence_id → ValidationError
    let bad_ev = EventInput {
        title: "Event".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: None,
        related_entity_id: None,
        related_evidence_id: Some("EV-GHOST".into()),
    };
    let err = add_event(&pool, &case_id, &bad_ev).await.unwrap_err();
    assert!(matches!(err, AppError::ValidationError { .. }), "missing evidence FK must be rejected: {err:?}");

    // Valid FK references
    let entity_id = make_entity(&pool, &case_id, "Alice", "person").await;
    let ev_id = make_evidence(&pool, &case_id, "EV-002").await;

    let ok = EventInput {
        title: "Event with refs".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: None,
        related_entity_id: Some(entity_id),
        related_evidence_id: Some(ev_id),
    };
    add_event(&pool, &case_id, &ok).await.expect("valid FK refs must be accepted");
}

// ─── Test 12: Graph assembly happy path ──────────────────────────────────────

#[tokio::test]
async fn test_graph_happy_path() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "GRAPH-01").await;

    // 3 entities + 2 evidence
    let a = make_entity(&pool, &case_id, "Alice", "person").await;
    let b = make_entity(&pool, &case_id, "Bob", "person").await;
    let c = make_entity(&pool, &case_id, "Acme Corp", "business").await;
    let ev1 = make_evidence(&pool, &case_id, "EV-G-001").await;
    let ev2 = make_evidence(&pool, &case_id, "EV-G-002").await;

    // 4 links: A→B, B→C, A→ev1, C→ev2
    let pairs: &[(&str, String, &str, String)] = &[
        ("entity", a.to_string(), "entity", b.to_string()),
        ("entity", b.to_string(), "entity", c.to_string()),
        ("entity", a.to_string(), "evidence", ev1.clone()),
        ("entity", c.to_string(), "evidence", ev2.clone()),
    ];
    for (src_t, src_id, tgt_t, tgt_id) in pairs {
        let input = LinkInput {
            source_type: src_t.to_string(),
            source_id: src_id.clone(),
            target_type: tgt_t.to_string(),
            target_id: tgt_id.clone(),
            link_label: None,
            directional: None,
            weight: None,
            notes: None,
        };
        add_link(&pool, &case_id, &input).await.expect("add link");
    }

    let filter = GraphFilter {
        entity_types: None,
        include_evidence: true,
    };
    let payload = build_graph(&pool, &case_id, &filter).await.expect("build_graph failed");

    assert_eq!(payload.nodes.len(), 5, "expected 5 nodes (3 entities + 2 evidence)");
    assert_eq!(payload.edges.len(), 4, "expected 4 edges");

    // Verify node ids
    let node_ids: std::collections::HashSet<_> = payload.nodes.iter().map(|n| n.id.clone()).collect();
    assert!(node_ids.contains(&format!("entity:{a}")));
    assert!(node_ids.contains(&format!("entity:{b}")));
    assert!(node_ids.contains(&format!("entity:{c}")));
    assert!(node_ids.contains(&format!("evidence:{ev1}")));
    assert!(node_ids.contains(&format!("evidence:{ev2}")));

    // All edge endpoints must exist in the node set
    for edge in &payload.edges {
        assert!(node_ids.contains(&edge.source), "edge.source '{}' not in nodes", edge.source);
        assert!(node_ids.contains(&edge.target), "edge.target '{}' not in nodes", edge.target);
    }
}

// ─── Test 13: Graph with entity_type filter ───────────────────────────────────

#[tokio::test]
async fn test_graph_entity_type_filter() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "GRAPH-02").await;

    let person_id = make_entity(&pool, &case_id, "Alice", "person").await;
    let biz_id = make_entity(&pool, &case_id, "Acme", "business").await;

    // Link person → business
    let link_input = LinkInput {
        source_type: "entity".into(),
        source_id: person_id.to_string(),
        target_type: "entity".into(),
        target_id: biz_id.to_string(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
    };
    add_link(&pool, &case_id, &link_input).await.expect("add link");

    // Filter to only "person"
    let filter = GraphFilter {
        entity_types: Some(vec!["person".into()]),
        include_evidence: false,
    };
    let payload = build_graph(&pool, &case_id, &filter).await.expect("build_graph");

    // Only the person node
    assert_eq!(payload.nodes.len(), 1, "expected only 1 person node, got {}", payload.nodes.len());
    assert_eq!(payload.nodes[0].id, format!("entity:{person_id}"));

    // The link touches business which is filtered out → no edges
    assert_eq!(payload.edges.len(), 0, "edge touching filtered entity must be excluded");
}

// ─── Test 14: Graph with include_evidence=false ───────────────────────────────

#[tokio::test]
async fn test_graph_no_evidence() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "GRAPH-03").await;

    let person_id = make_entity(&pool, &case_id, "Alice", "person").await;
    let ev_id = make_evidence(&pool, &case_id, "EV-H-001").await;

    // Link person → evidence
    let link_input = LinkInput {
        source_type: "entity".into(),
        source_id: person_id.to_string(),
        target_type: "evidence".into(),
        target_id: ev_id.clone(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
    };
    add_link(&pool, &case_id, &link_input).await.expect("add link");

    let filter = GraphFilter {
        entity_types: None,
        include_evidence: false,
    };
    let payload = build_graph(&pool, &case_id, &filter).await.expect("build_graph");

    // No evidence nodes
    assert!(
        payload.nodes.iter().all(|n| n.kind != "evidence"),
        "no evidence nodes expected when include_evidence=false"
    );

    // Edge touching evidence is excluded
    assert_eq!(payload.edges.len(), 0, "edge to evidence must be excluded when evidence not in node set");
}

// ─── Test 15: Graph excludes soft-deleted entities and links ──────────────────

#[tokio::test]
async fn test_graph_excludes_soft_deleted() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "GRAPH-04").await;

    let a = make_entity(&pool, &case_id, "Alice", "person").await;
    let b = make_entity(&pool, &case_id, "Bob", "person").await;

    let link_input = LinkInput {
        source_type: "entity".into(),
        source_id: a.to_string(),
        target_type: "entity".into(),
        target_id: b.to_string(),
        link_label: None,
        directional: None,
        weight: None,
        notes: None,
    };
    add_link(&pool, &case_id, &link_input).await.expect("add link");

    // Soft-delete entity A (cascades to link)
    entity_soft_delete(&pool, a).await.expect("soft delete A");

    let filter = GraphFilter {
        entity_types: None,
        include_evidence: false,
    };
    let payload = build_graph(&pool, &case_id, &filter).await.expect("build_graph");

    // Only B remains
    assert_eq!(payload.nodes.len(), 1, "soft-deleted entity A must not appear in graph");
    assert_eq!(payload.nodes[0].id, format!("entity:{b}"));
    // Link is cascade-deleted — no edges
    assert_eq!(payload.edges.len(), 0, "edge involving deleted entity must not appear");
}

// ─── Test 16: Crime line assembly (all 6 groups) ─────────────────────────────

#[tokio::test]
async fn test_crime_line_all_groups() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "CRIME-01").await;

    // Evidence
    let ev_id = make_evidence(&pool, &case_id, "EV-CL-001").await;

    // Custody
    let cust_input = CustodyInput {
        action: "Seized".into(),
        from_party: "Scene".into(),
        to_party: "Officer".into(),
        location: None,
        custody_datetime: past_dt(),
        purpose: None,
        notes: None,
    };
    add_custody(&pool, &ev_id, &cust_input).await.expect("add custody");

    // Hash — verification_datetime is NaiveDateTime (not Option)
    let hash_input = HashInput {
        algorithm: "SHA256".into(),
        hash_value: "a".repeat(64),
        verified_by: "Alice".into(),
        verification_datetime: past_dt(),
        notes: None,
    };
    add_hash(&pool, &ev_id, &hash_input).await.expect("add hash");

    // Tool
    let tool_input = ToolInput {
        evidence_id: None,
        tool_name: "FTK".into(),
        version: Some("7.0".into()),
        purpose: "Imaging".into(),
        command_used: None,
        input_file: None,
        output_file: None,
        execution_datetime: Some(past_dt()),
        operator: "Alice".into(),
    };
    add_tool(&pool, &case_id, &tool_input).await.expect("add tool");

    // Analysis note
    let analysis_input = AnalysisInput {
        evidence_id: None,
        category: "Observation".into(),
        finding: "Key finding about the suspect".into(),
        description: None,
        confidence_level: None,
    };
    add_analysis(&pool, &case_id, &analysis_input).await.expect("add analysis");

    // Case event
    let evt_input = EventInput {
        title: "Suspect meeting".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: Some("observation".into()),
        related_entity_id: None,
        related_evidence_id: None,
    };
    add_event(&pool, &case_id, &evt_input).await.expect("add event");

    let filter = TimelineFilter { start: None, end: None };
    let payload = build_crime_line(&pool, &case_id, &filter)
        .await
        .expect("build_crime_line failed");

    // 6 hardcoded groups
    assert_eq!(payload.groups.len(), 6, "expected 6 timeline groups");

    let group_ids: Vec<_> = payload.groups.iter().map(|g| g.id.as_str()).collect();
    for g in &["events", "evidence", "custody", "hashes", "tools", "analysis"] {
        assert!(group_ids.contains(g), "group '{g}' missing from groups list");
    }

    // At least one item from each group
    let item_groups: std::collections::HashSet<_> =
        payload.items.iter().map(|i| i.group.as_str()).collect();
    for g in &["events", "evidence", "custody", "hashes", "tools", "analysis"] {
        assert!(item_groups.contains(g), "group '{g}' must have at least one item in crime line");
    }

    // Items must be sorted by start ASC
    for w in payload.items.windows(2) {
        assert!(w[0].start <= w[1].start, "items must be sorted by start ASC");
    }
}

// ─── Test 17: Crime line date range filter ────────────────────────────────────

#[tokio::test]
async fn test_crime_line_date_range_filter() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "CRIME-02").await;

    // Create events spread over a month; stop before current time to avoid future validation error.
    let base = Utc::now().naive_utc() - Duration::days(30);
    let now = Utc::now().naive_utc();

    let mut added = 0usize;
    for i in 0..30i64 {
        let dt = base + Duration::days(i);
        if dt >= now {
            break;
        }
        let input = EventInput {
            title: format!("Event day {i}"),
            description: None,
            event_datetime: dt,
            event_end_datetime: None,
            category: None,
            related_entity_id: None,
            related_evidence_id: None,
        };
        add_event(&pool, &case_id, &input).await.expect("add event");
        added += 1;
    }

    assert!(added > 14, "need >14 events for the filter test to be meaningful (got {added})");

    // Filter to a 7-day window: days 10–17
    let window_start = base + Duration::days(10);
    let window_end = base + Duration::days(17);

    let filter = TimelineFilter {
        start: Some(window_start),
        end: Some(window_end),
    };
    let payload = build_crime_line(&pool, &case_id, &filter)
        .await
        .expect("build_crime_line with filter failed");

    // All returned items must be within the window
    for item in &payload.items {
        assert!(
            item.start >= window_start && item.start <= window_end,
            "item {} (start {:?}) is outside filter window [{:?}, {:?}]",
            item.id, item.start, window_start, window_end
        );
    }

    // Must have fewer items than without filter
    assert!(
        !payload.items.is_empty(),
        "at least one event should be within the 7-day window"
    );
    assert!(
        payload.items.len() < added,
        "filter should exclude most events; got {} out of {added}",
        payload.items.len()
    );
}

// ─── Test 18: Crime line excludes soft-deleted events ────────────────────────

#[tokio::test]
async fn test_crime_line_excludes_soft_deleted_events() {
    let (_, pool) = make_state().await;
    let case_id = make_case(&pool, "CRIME-03").await;

    // Add an event and then soft-delete it
    let evt_input = EventInput {
        title: "Event to delete".into(),
        description: None,
        event_datetime: past_dt(),
        event_end_datetime: None,
        category: None,
        related_entity_id: None,
        related_evidence_id: None,
    };
    let event = add_event(&pool, &case_id, &evt_input).await.expect("add event");

    // Add evidence (auto-derived — not soft-deleted even if entity is)
    make_evidence(&pool, &case_id, "EV-CL-003").await;

    // Soft-delete the event
    event_soft_delete(&pool, event.event_id).await.expect("soft delete event");

    let filter = TimelineFilter { start: None, end: None };
    let payload = build_crime_line(&pool, &case_id, &filter).await.expect("crime line");

    // No event items (soft-deleted)
    let event_items: Vec<_> = payload.items.iter().filter(|i| i.group == "events").collect();
    assert!(
        event_items.is_empty(),
        "soft-deleted event must not appear in crime line, found {} items",
        event_items.len()
    );

    // Evidence items DO appear (auto-derived, evidence table has no is_deleted)
    let ev_items: Vec<_> = payload.items.iter().filter(|i| i.group == "evidence").collect();
    assert!(
        !ev_items.is_empty(),
        "auto-derived evidence items must appear in crime line regardless of event deletion"
    );
}

// ─── Test 19: Session guard negative tests ────────────────────────────────────

/// The session guard lives in the Tauri command layer (not the db:: functions).
/// We verify it directly via `require_session` — the same function every command
/// calls as its first statement.

#[tokio::test]
async fn test_session_guard_invalid_token_rejected() {
    let (state, _) = make_state().await;

    let err = dfars_desktop_lib::auth::session::require_session(&state, "sess_invalid_token_xyz");
    assert!(
        matches!(err, Err(AppError::Unauthorized)),
        "invalid token must return Unauthorized: {err:?}"
    );
}

#[tokio::test]
async fn test_session_guard_empty_token_rejected() {
    let (state, _) = make_state().await;

    let err = dfars_desktop_lib::auth::session::require_session(&state, "");
    assert!(
        matches!(err, Err(AppError::Unauthorized)),
        "empty token must return Unauthorized: {err:?}"
    );
}

#[tokio::test]
async fn test_session_guard_entity_group_rejected() {
    let (state, _) = make_state().await;
    let err = dfars_desktop_lib::auth::session::require_session(&state, "sess_no_such_entity_token");
    assert!(matches!(err, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn test_session_guard_link_group_rejected() {
    let (state, _) = make_state().await;
    let err = dfars_desktop_lib::auth::session::require_session(&state, "sess_no_such_link_token");
    assert!(matches!(err, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn test_session_guard_event_group_rejected() {
    let (state, _) = make_state().await;
    let err = dfars_desktop_lib::auth::session::require_session(&state, "sess_no_such_event_token");
    assert!(matches!(err, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn test_session_guard_aggregate_commands_rejected() {
    let (state, _) = make_state().await;
    // case_graph and case_crime_line both require a valid session
    let err = dfars_desktop_lib::auth::session::require_session(&state, "sess_fake_aggregate");
    assert!(matches!(err, Err(AppError::Unauthorized)));
}

/// Positive control: a valid verified session IS accepted.
#[tokio::test]
async fn test_session_guard_valid_token_accepted() {
    let (state, _) = make_state().await;
    let token = state.sessions.create_verified("tester");
    let result = dfars_desktop_lib::auth::session::require_session(&state, &token);
    assert!(result.is_ok(), "valid verified session token must be accepted: {result:?}");
}
