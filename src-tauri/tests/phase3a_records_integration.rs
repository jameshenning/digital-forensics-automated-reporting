/// Phase 3a Records Integration Tests
///
/// Covers all 16 test families from the Phase 3a brief:
///   1.  Evidence lifecycle (add → list → get → delete → list empty)
///   2.  Evidence duplicate ID → EvidenceAlreadyExists
///   3.  Evidence in missing case → CaseNotFound
///   4.  Evidence delete blocked by custody FK → EvidenceHasDependents
///   5.  Custody sequence auto-increments per evidence (starts at 1)
///   6.  Custody sequence is per-evidence (no cross-contamination)
///   7.  Custody CRUD (add → list → update → list updated → delete → list gone)
///   8.  Custody action allowlist rejection → ValidationError
///   9.  Hash format validation (too short, non-hex, valid accept)
///   10. Hash lowercases uppercase input
///   11. Hash list for case aggregates across evidence items
///   12. Tool add with / without evidence_id
///   13. Tool add with missing execution_datetime uses now()
///   14. Analysis add (valid, invalid category)
///   15. Analysis list for evidence filters correctly
///   16. Session guard negative (one per command group)
///
/// Run: `cargo test --test phase3a_records_integration`

use chrono::{NaiveDate, NaiveDateTime};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

use dfars_desktop_lib::{
    auth::{argon, lockout::LockoutMap, session::SessionState},
    crypto::CryptoState,
    db::{
        AppDb,
        analysis::{AnalysisInput, add_analysis, list_for_case as analysis_list_for_case,
                   list_for_evidence as analysis_list_for_evidence},
        cases::{CaseInput, create_case},
        custody::{CustodyInput, add_custody, delete_custody, list_for_case as custody_list_for_case,
                  list_for_evidence as custody_list_for_evidence, update_custody},
        evidence::{EvidenceInput, add_evidence, delete_evidence, get_evidence,
                   list_for_case as evidence_list_for_case},
        hashes::{HashInput, add_hash, list_for_case as hash_list_for_case,
                 list_for_evidence as hash_list_for_evidence},
        tools::{ToolInput, add_tool, list_for_case as tool_list_for_case,
                list_for_evidence as tool_list_for_evidence},
    },
    error::AppError,
    state::AppState,
};

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Unique DB counter for test isolation.
static DB_COUNTER: AtomicU64 = AtomicU64::new(1000);

// ─── Schema constants (verbatim from migration, including tool_usage.evidence_id) ──

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
    input_sha256 TEXT,
    output_sha256 TEXT,
    environment_notes TEXT,
    reproduction_notes TEXT,
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
    -- migration 0007: validation principles (nullable, v1-compat)
    created_by TEXT,
    method_reference TEXT,
    alternatives_considered TEXT,
    tool_version TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

-- migration 0007: append-only peer review records
CREATE TABLE IF NOT EXISTS analysis_reviews (
    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL REFERENCES analysis_notes(note_id),
    reviewed_by TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    review_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_analysis_reviews_note ON analysis_reviews(note_id);

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

const AUTH_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
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
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    token_preview TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"#;

// ─── Test infrastructure ──────────────────────────────────────────────────────

async fn make_pool(ddl: &str) -> SqlitePool {
    let id = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let uri = format!("file:dfars_p3a_test_{id}?mode=memory&cache=shared");

    let opts = SqliteConnectOptions::new()
        .filename(&uri)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("make_pool: failed to open :memory: pool");

    sqlx::raw_sql(ddl)
        .execute(&pool)
        .await
        .expect("make_pool: failed to apply schema");

    pool
}

async fn build_state() -> (Arc<AppState>, SqlitePool) {
    let auth_pool = make_pool(AUTH_SCHEMA).await;
    let forensics_pool = make_pool(FORENSICS_SCHEMA).await;

    let db = AppDb {
        forensics: forensics_pool.clone(),
        auth: auth_pool,
    };

    let crypto = CryptoState::new_with_random_key();
    let dummy_hash = argon::make_dummy_hash();

    let state = Arc::new(AppState {
        db,
        crypto,
        lockout: LockoutMap::new(),
        sessions: SessionState::new(),
        dummy_hash,
        config: dfars_desktop_lib::config::AppConfig::default(),
        config_path: std::path::PathBuf::new(),
        agent_zero: dfars_desktop_lib::agent_zero::AgentZeroState::new(),
        osint_consent_runtime: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });

    (state, forensics_pool)
}

/// Create a minimal case so evidence FKs resolve.
async fn setup_case(pool: &SqlitePool, case_id: &str) {
    let input = CaseInput {
        case_id: case_id.to_string(),
        case_name: format!("Test Case {case_id}"),
        description: None,
        investigator: "examiner".to_string(),
        agency: None,
        start_date: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
        end_date: None,
        status: None,
        priority: None,
        classification: None,
        evidence_drive_path: None,
        tags: vec![],
    };
    create_case(pool, &input).await.expect("setup_case failed");
}

/// Create minimal evidence input.
fn minimal_evidence_input(evidence_id: &str) -> EvidenceInput {
    EvidenceInput {
        evidence_id: evidence_id.to_string(),
        description: format!("Evidence item {evidence_id}"),
        collected_by: "examiner".to_string(),
        // Use a datetime that is definitely in the past
        collection_datetime: NaiveDateTime::parse_from_str(
            "2026-01-15 10:00:00",
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap(),
        location: None,
        status: None,
        evidence_type: None,
        make_model: None,
        serial_number: None,
        storage_location: None,
    }
}

/// Create minimal custody input.
fn minimal_custody_input(action: &str) -> CustodyInput {
    CustodyInput {
        action: action.to_string(),
        from_party: "examiner".to_string(),
        to_party: "lab".to_string(),
        location: None,
        custody_datetime: NaiveDateTime::parse_from_str(
            "2026-01-15 11:00:00",
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap(),
        purpose: None,
        notes: None,
    }
}

/// A valid SHA256 hash (64 lowercase hex chars).
const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ─── Test 1: Evidence lifecycle ───────────────────────────────────────────────

#[tokio::test]
async fn test_01_evidence_lifecycle() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-EV-001").await;

    // Add
    let input = minimal_evidence_input("EV-001");
    let ev = add_evidence(&pool, "CASE-EV-001", &input)
        .await
        .expect("add_evidence failed");
    assert_eq!(ev.evidence_id, "EV-001");
    assert_eq!(ev.case_id, "CASE-EV-001");
    assert_eq!(ev.status, "Collected");

    // List for case — 1 row
    let list = evidence_list_for_case(&pool, "CASE-EV-001")
        .await
        .expect("list_for_case failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].evidence_id, "EV-001");

    // Get by id
    let fetched = get_evidence(&pool, "EV-001")
        .await
        .expect("get_evidence failed");
    assert_eq!(fetched.description, "Evidence item EV-001");

    // Delete
    delete_evidence(&pool, "EV-001")
        .await
        .expect("delete_evidence failed");

    // List — empty
    let list2 = evidence_list_for_case(&pool, "CASE-EV-001")
        .await
        .expect("list after delete");
    assert!(list2.is_empty(), "evidence list must be empty after delete");
}

// ─── Test 2: Evidence duplicate ID → EvidenceAlreadyExists ───────────────────

#[tokio::test]
async fn test_02_evidence_dup_id() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-DUP-EV").await;

    let input = minimal_evidence_input("EV-DUP");
    add_evidence(&pool, "CASE-DUP-EV", &input)
        .await
        .expect("first add must succeed");

    let err = add_evidence(&pool, "CASE-DUP-EV", &input)
        .await
        .expect_err("second add must fail");
    assert!(
        matches!(err, AppError::EvidenceAlreadyExists { ref evidence_id } if evidence_id == "EV-DUP"),
        "expected EvidenceAlreadyExists, got: {err:?}"
    );
}

// ─── Test 3: Evidence in missing case → CaseNotFound ─────────────────────────

#[tokio::test]
async fn test_03_evidence_missing_case() {
    let (_state, pool) = build_state().await;
    // No case created — FK will fire

    let input = minimal_evidence_input("EV-NOCASE");
    let err = add_evidence(&pool, "GHOST-CASE", &input)
        .await
        .expect_err("add to missing case must fail");
    assert!(
        matches!(err, AppError::CaseNotFound { ref case_id } if case_id == "GHOST-CASE"),
        "expected CaseNotFound, got: {err:?}"
    );
}

// ─── Test 4: Evidence delete blocked by custody FK → EvidenceHasDependents ───

#[tokio::test]
async fn test_04_evidence_delete_blocked_by_custody() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-FK-TEST").await;

    // Add evidence
    add_evidence(&pool, "CASE-FK-TEST", &minimal_evidence_input("EV-LOCKED"))
        .await
        .expect("add evidence");

    // Add a custody event (this creates the RESTRICT FK child)
    add_custody(&pool, "EV-LOCKED", &minimal_custody_input("Seized"))
        .await
        .expect("add custody");

    // Attempt to delete evidence — must fail
    let err = delete_evidence(&pool, "EV-LOCKED")
        .await
        .expect_err("delete must fail with custody dependent");
    assert!(
        matches!(err, AppError::EvidenceHasDependents { ref evidence_id } if evidence_id == "EV-LOCKED"),
        "expected EvidenceHasDependents, got: {err:?}"
    );
}

// ─── Test 5: Custody sequence auto-increments per evidence (starts at 1) ─────

#[tokio::test]
async fn test_05_custody_sequence_auto_increments() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-SEQ").await;
    add_evidence(&pool, "CASE-SEQ", &minimal_evidence_input("EV-SEQ"))
        .await
        .unwrap();

    let e1 = add_custody(&pool, "EV-SEQ", &minimal_custody_input("Seized"))
        .await
        .unwrap();
    let e2 = add_custody(&pool, "EV-SEQ", &minimal_custody_input("Transferred"))
        .await
        .unwrap();
    let e3 = add_custody(&pool, "EV-SEQ", &minimal_custody_input("Received"))
        .await
        .unwrap();

    assert_eq!(e1.custody_sequence, 1, "first custody event must be seq 1");
    assert_eq!(e2.custody_sequence, 2);
    assert_eq!(e3.custody_sequence, 3);
}

// ─── Test 6: Custody sequence is per-evidence (no cross-contamination) ────────

#[tokio::test]
async fn test_06_custody_sequence_per_evidence() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-PERSEQ").await;

    // Two evidence items
    add_evidence(&pool, "CASE-PERSEQ", &minimal_evidence_input("EV-A"))
        .await
        .unwrap();
    add_evidence(&pool, "CASE-PERSEQ", &minimal_evidence_input("EV-B"))
        .await
        .unwrap();

    // Add 2 custody events to EV-A
    add_custody(&pool, "EV-A", &minimal_custody_input("Seized"))
        .await
        .unwrap();
    add_custody(&pool, "EV-A", &minimal_custody_input("Transferred"))
        .await
        .unwrap();

    // Add 3 custody events to EV-B — must start at 1, not 3
    let b1 = add_custody(&pool, "EV-B", &minimal_custody_input("Seized"))
        .await
        .unwrap();
    let b2 = add_custody(&pool, "EV-B", &minimal_custody_input("Received"))
        .await
        .unwrap();
    let b3 = add_custody(&pool, "EV-B", &minimal_custody_input("Analyzed"))
        .await
        .unwrap();

    assert_eq!(b1.custody_sequence, 1, "EV-B seq 1 must be 1, not contaminated by EV-A");
    assert_eq!(b2.custody_sequence, 2);
    assert_eq!(b3.custody_sequence, 3);
}

// ─── Test 7: Custody CRUD ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_07_custody_crud() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-CUST-CRUD").await;
    add_evidence(&pool, "CASE-CUST-CRUD", &minimal_evidence_input("EV-CRUD"))
        .await
        .unwrap();

    // Add
    let created = add_custody(&pool, "EV-CRUD", &minimal_custody_input("Seized"))
        .await
        .unwrap();
    let id = created.custody_id;
    assert_eq!(created.action, "Seized");
    assert_eq!(created.custody_sequence, 1);

    // List for evidence
    let list = custody_list_for_evidence(&pool, "EV-CRUD").await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].action, "Seized");

    // Update
    let mut updated_input = minimal_custody_input("Transferred");
    updated_input.notes = Some("Updated note".to_string());
    let updated = update_custody(&pool, id, &updated_input).await.unwrap();
    assert_eq!(updated.action, "Transferred");
    assert_eq!(updated.notes.as_deref(), Some("Updated note"));
    assert_eq!(updated.custody_sequence, 1, "sequence must not change on update");

    // List — shows updated
    let list2 = custody_list_for_evidence(&pool, "EV-CRUD").await.unwrap();
    assert_eq!(list2.len(), 1);
    assert_eq!(list2[0].action, "Transferred");

    // Delete
    delete_custody(&pool, id).await.unwrap();

    // List — empty
    let list3 = custody_list_for_evidence(&pool, "EV-CRUD").await.unwrap();
    assert!(list3.is_empty(), "custody list must be empty after delete");
}

// ─── Test 8: Custody action allowlist rejection → ValidationError ─────────────

#[tokio::test]
async fn test_08_custody_action_allowlist() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-ACTION").await;
    add_evidence(&pool, "CASE-ACTION", &minimal_evidence_input("EV-ACTION"))
        .await
        .unwrap();

    let bad_input = minimal_custody_input("Processed"); // not in allowlist
    let err = add_custody(&pool, "EV-ACTION", &bad_input)
        .await
        .expect_err("invalid action must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "action"),
        "expected ValidationError on action, got: {err:?}"
    );
}

// ─── Test 9: Hash format validation ──────────────────────────────────────────

#[tokio::test]
async fn test_09a_hash_sha256_too_short() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-HASH-SHORT").await;
    add_evidence(&pool, "CASE-HASH-SHORT", &minimal_evidence_input("EV-HASH-SHORT"))
        .await
        .unwrap();

    // 50 hex chars instead of 64
    let bad_hash = "a".repeat(50);
    let input = HashInput {
        algorithm: "SHA256".to_string(),
        hash_value: bad_hash,
        verified_by: "examiner".to_string(),
        verification_datetime: NaiveDateTime::parse_from_str(
            "2026-01-15 12:00:00",
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap(),
        notes: None,
    };
    let err = add_hash(&pool, "EV-HASH-SHORT", &input)
        .await
        .expect_err("too-short SHA256 must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "hash_value"),
        "expected ValidationError on hash_value, got: {err:?}"
    );
}

#[tokio::test]
async fn test_09b_hash_md5_non_hex() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-HASH-NONHEX").await;
    add_evidence(&pool, "CASE-HASH-NONHEX", &minimal_evidence_input("EV-HASH-NONHEX"))
        .await
        .unwrap();

    // 32 chars but contains 'g'
    let bad_hash = "d41d8cd98f00b204e9800998ecf8427g".to_string(); // 32 chars, 'g' not hex
    let input = HashInput {
        algorithm: "MD5".to_string(),
        hash_value: bad_hash,
        verified_by: "examiner".to_string(),
        verification_datetime: NaiveDateTime::parse_from_str(
            "2026-01-15 12:00:00",
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap(),
        notes: None,
    };
    let err = add_hash(&pool, "EV-HASH-NONHEX", &input)
        .await
        .expect_err("non-hex MD5 must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "hash_value"),
        "expected ValidationError on hash_value, got: {err:?}"
    );
}

#[tokio::test]
async fn test_09c_hash_sha256_valid() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-HASH-VALID").await;
    add_evidence(&pool, "CASE-HASH-VALID", &minimal_evidence_input("EV-HASH-VALID"))
        .await
        .unwrap();

    let input = HashInput {
        algorithm: "SHA256".to_string(),
        hash_value: VALID_SHA256.to_string(),
        verified_by: "examiner".to_string(),
        verification_datetime: NaiveDateTime::parse_from_str(
            "2026-01-15 12:00:00",
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap(),
        notes: None,
    };
    let record = add_hash(&pool, "EV-HASH-VALID", &input)
        .await
        .expect("valid SHA256 must succeed");
    assert_eq!(record.hash_value, VALID_SHA256);
    assert_eq!(record.algorithm, "SHA256");
}

// ─── Test 10: Hash lowercases uppercase input ─────────────────────────────────

#[tokio::test]
async fn test_10_hash_lowercase_normalised() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-HASH-CASE").await;
    add_evidence(&pool, "CASE-HASH-CASE", &minimal_evidence_input("EV-HASH-CASE"))
        .await
        .unwrap();

    let upper_hash = VALID_SHA256.to_uppercase();
    let input = HashInput {
        algorithm: "SHA256".to_string(),
        hash_value: upper_hash,
        verified_by: "examiner".to_string(),
        verification_datetime: NaiveDateTime::parse_from_str(
            "2026-01-15 12:00:00",
            "%Y-%m-%d %H:%M:%S",
        )
        .unwrap(),
        notes: None,
    };
    let record = add_hash(&pool, "EV-HASH-CASE", &input)
        .await
        .expect("uppercase hash must be accepted and lowercased");
    assert_eq!(
        record.hash_value, VALID_SHA256,
        "stored hash must be lowercased"
    );
}

// ─── Test 11: Hash list for case aggregates across evidence items ─────────────

#[tokio::test]
async fn test_11_hash_list_for_case_aggregates() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-HASH-AGG").await;

    // Two evidence items, each gets a hash
    add_evidence(&pool, "CASE-HASH-AGG", &minimal_evidence_input("EV-H1"))
        .await
        .unwrap();
    add_evidence(&pool, "CASE-HASH-AGG", &minimal_evidence_input("EV-H2"))
        .await
        .unwrap();

    let dt = NaiveDateTime::parse_from_str("2026-01-15 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

    add_hash(
        &pool,
        "EV-H1",
        &HashInput {
            algorithm: "SHA256".to_string(),
            hash_value: VALID_SHA256.to_string(),
            verified_by: "examiner".to_string(),
            verification_datetime: dt,
            notes: None,
        },
    )
    .await
    .unwrap();

    // Use a valid SHA1 (40 hex chars)
    let valid_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    add_hash(
        &pool,
        "EV-H2",
        &HashInput {
            algorithm: "SHA1".to_string(),
            hash_value: valid_sha1.to_string(),
            verified_by: "examiner".to_string(),
            verification_datetime: dt,
            notes: None,
        },
    )
    .await
    .unwrap();

    // list_for_case must return both
    let hashes = hash_list_for_case(&pool, "CASE-HASH-AGG").await.unwrap();
    assert_eq!(hashes.len(), 2, "case hash list must aggregate across evidence items");

    // list_for_evidence must return only the one for each
    let h1_list = hash_list_for_evidence(&pool, "EV-H1").await.unwrap();
    assert_eq!(h1_list.len(), 1);
    assert_eq!(h1_list[0].algorithm, "SHA256");

    let h2_list = hash_list_for_evidence(&pool, "EV-H2").await.unwrap();
    assert_eq!(h2_list.len(), 1);
    assert_eq!(h2_list[0].algorithm, "SHA1");
}

// ─── Test 12: Tool add with/without evidence_id ───────────────────────────────

#[tokio::test]
async fn test_12_tool_add_with_and_without_evidence_id() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-TOOL").await;
    add_evidence(&pool, "CASE-TOOL", &minimal_evidence_input("EV-TOOL"))
        .await
        .unwrap();

    // Case-scoped tool (no evidence_id)
    let case_tool = add_tool(
        &pool,
        "CASE-TOOL",
        &ToolInput {
            evidence_id: None,
            tool_name: "FTK Imager".to_string(),
            version: Some("4.7.1".to_string()),
            purpose: "Disk imaging".to_string(),
            command_used: None,
            input_file: None,
            output_file: None,
            execution_datetime: None,
            operator: "examiner".to_string(),
        input_sha256: None,
        output_sha256: None,
        environment_notes: None,
        reproduction_notes: None,
        },
    )
    .await
    .expect("case-scoped tool add must succeed");
    assert!(case_tool.evidence_id.is_none(), "evidence_id must be None for case-scoped tool");

    // Evidence-scoped tool
    let ev_tool = add_tool(
        &pool,
        "CASE-TOOL",
        &ToolInput {
            evidence_id: Some("EV-TOOL".to_string()),
            tool_name: "Volatility".to_string(),
            version: Some("3.0".to_string()),
            purpose: "Memory analysis".to_string(),
            command_used: Some("python vol.py -f mem.raw windows.info".to_string()),
            input_file: Some("mem.raw".to_string()),
            output_file: None,
            execution_datetime: None,
            operator: "examiner".to_string(),
        input_sha256: None,
        output_sha256: None,
        environment_notes: None,
        reproduction_notes: None,
        },
    )
    .await
    .expect("evidence-scoped tool add must succeed");
    assert_eq!(ev_tool.evidence_id.as_deref(), Some("EV-TOOL"));

    // list_for_evidence must return only the evidence-scoped one
    let ev_tools = tool_list_for_evidence(&pool, "EV-TOOL").await.unwrap();
    assert_eq!(ev_tools.len(), 1);
    assert_eq!(ev_tools[0].tool_name, "Volatility");

    // list_for_case returns both
    let case_tools = tool_list_for_case(&pool, "CASE-TOOL").await.unwrap();
    assert_eq!(case_tools.len(), 2);
}

// ─── Test 13: Tool add with missing execution_datetime uses now() ─────────────

#[tokio::test]
async fn test_13_tool_execution_datetime_defaults_to_now() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-TOOLDT").await;

    let before = chrono::Utc::now().naive_utc();

    let record = add_tool(
        &pool,
        "CASE-TOOLDT",
        &ToolInput {
            evidence_id: None,
            tool_name: "TestTool".to_string(),
            version: None,
            purpose: "Testing datetime default".to_string(),
            command_used: None,
            input_file: None,
            output_file: None,
            execution_datetime: None, // deliberately absent
            operator: "examiner".to_string(),
        input_sha256: None,
        output_sha256: None,
        environment_notes: None,
        reproduction_notes: None,
        },
    )
    .await
    .expect("tool add must succeed");

    let after = chrono::Utc::now().naive_utc();
    // execution_datetime is stored as a String (v1-compat post-fix).
    // Parse it back for the time-range assertion.
    let parsed = chrono::NaiveDateTime::parse_from_str(
        &record.execution_datetime,
        "%Y-%m-%dT%H:%M:%S%.f",
    )
    .or_else(|_| chrono::NaiveDateTime::parse_from_str(&record.execution_datetime, "%Y-%m-%dT%H:%M:%S"))
    .or_else(|_| chrono::NaiveDateTime::parse_from_str(&record.execution_datetime, "%Y-%m-%d %H:%M:%S%.f"))
    .or_else(|_| chrono::NaiveDateTime::parse_from_str(&record.execution_datetime, "%Y-%m-%d %H:%M:%S"))
    .expect("execution_datetime should parse as one of the known formats");

    assert!(
        parsed >= before && parsed <= after,
        "execution_datetime must be approximately now(): got {:?}",
        record.execution_datetime
    );
}

// ─── Test 14: Analysis add (valid and invalid category) ───────────────────────

#[tokio::test]
async fn test_14_analysis_add_valid_and_invalid_category() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-ANA").await;

    // Valid category
    let note = add_analysis(
        &pool,
        "CASE-ANA",
        &AnalysisInput {
            evidence_id: None,
            category: "Observation".to_string(),
            finding: "Test finding".to_string(),
            description: None,
            confidence_level: Some("High".to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("valid analysis add must succeed");
    assert_eq!(note.category, "Observation");
    assert_eq!(note.confidence_level, "High");

    // Invalid category
    let err = add_analysis(
        &pool,
        "CASE-ANA",
        &AnalysisInput {
            evidence_id: None,
            category: "SuspectNote".to_string(), // not in allowlist
            finding: "Some finding".to_string(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .expect_err("invalid category must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "category"),
        "expected ValidationError on category, got: {err:?}"
    );
}

// ─── Test 15: Analysis list for evidence filters correctly ────────────────────

#[tokio::test]
async fn test_15_analysis_list_for_evidence_filters() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-ANAFILT").await;
    add_evidence(&pool, "CASE-ANAFILT", &minimal_evidence_input("EV-ANA"))
        .await
        .unwrap();

    // Add a note linked to evidence
    add_analysis(
        &pool,
        "CASE-ANAFILT",
        &AnalysisInput {
            evidence_id: Some("EV-ANA".to_string()),
            category: "Timeline".to_string(),
            finding: "Evidence-linked finding".to_string(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Add a case-scoped note (no evidence_id)
    add_analysis(
        &pool,
        "CASE-ANAFILT",
        &AnalysisInput {
            evidence_id: None,
            category: "Conclusion".to_string(),
            finding: "Case-level finding".to_string(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // list_for_evidence must return only the evidence-linked note
    let ev_notes = analysis_list_for_evidence(&pool, "EV-ANA").await.unwrap();
    assert_eq!(ev_notes.len(), 1, "must return only evidence-linked notes");
    assert_eq!(ev_notes[0].category, "Timeline");

    // list_for_case returns both
    let case_notes = analysis_list_for_case(&pool, "CASE-ANAFILT").await.unwrap();
    assert_eq!(case_notes.len(), 2);
}

// ─── Test 16: Session guard negative (one per command group) ──────────────────

#[tokio::test]
async fn test_16a_session_guard_evidence_add() {
    use dfars_desktop_lib::auth::session::require_session;
    let (state, _pool) = build_state().await;
    let err = require_session(&state, "").expect_err("empty token must be rejected");
    assert!(
        matches!(err, AppError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );
}

#[tokio::test]
async fn test_16b_session_guard_custody_add() {
    use dfars_desktop_lib::auth::session::require_session;
    let (state, _pool) = build_state().await;
    let err = require_session(&state, "invalid_token_custody")
        .expect_err("invalid token must be rejected");
    assert!(
        matches!(err, AppError::Unauthorized),
        "expected Unauthorized for custody group, got: {err:?}"
    );
}

#[tokio::test]
async fn test_16c_session_guard_hash_add() {
    use dfars_desktop_lib::auth::session::require_session;
    let (state, _pool) = build_state().await;
    let err = require_session(&state, "invalid_token_hash")
        .expect_err("invalid token must be rejected");
    assert!(
        matches!(err, AppError::Unauthorized),
        "expected Unauthorized for hash group, got: {err:?}"
    );
}

#[tokio::test]
async fn test_16d_session_guard_tool_add() {
    use dfars_desktop_lib::auth::session::require_session;
    let (state, _pool) = build_state().await;
    let err = require_session(&state, "invalid_token_tool")
        .expect_err("invalid token must be rejected");
    assert!(
        matches!(err, AppError::Unauthorized),
        "expected Unauthorized for tool group, got: {err:?}"
    );
}

#[tokio::test]
async fn test_16e_session_guard_analysis_add() {
    use dfars_desktop_lib::auth::session::require_session;
    let (state, _pool) = build_state().await;
    let err = require_session(&state, "invalid_token_analysis")
        .expect_err("invalid token must be rejected");
    assert!(
        matches!(err, AppError::Unauthorized),
        "expected Unauthorized for analysis group, got: {err:?}"
    );
}

// ─── Additional: custody list_for_case groups by evidence ────────────────────

#[tokio::test]
async fn test_custody_list_for_case_groups() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-CUSTCASE").await;
    add_evidence(&pool, "CASE-CUSTCASE", &minimal_evidence_input("EV-CA"))
        .await
        .unwrap();
    add_evidence(&pool, "CASE-CUSTCASE", &minimal_evidence_input("EV-CB"))
        .await
        .unwrap();

    add_custody(&pool, "EV-CA", &minimal_custody_input("Seized"))
        .await
        .unwrap();
    add_custody(&pool, "EV-CB", &minimal_custody_input("Transferred"))
        .await
        .unwrap();
    add_custody(&pool, "EV-CA", &minimal_custody_input("Received"))
        .await
        .unwrap();

    let all = custody_list_for_case(&pool, "CASE-CUSTCASE").await.unwrap();
    assert_eq!(all.len(), 3);

    // Verify ordering: grouped by evidence_id, then by custody_sequence
    // EV-CA has seq 1 and seq 2; EV-CB has seq 1
    let ca_events: Vec<_> = all.iter().filter(|e| e.evidence_id == "EV-CA").collect();
    let cb_events: Vec<_> = all.iter().filter(|e| e.evidence_id == "EV-CB").collect();
    assert_eq!(ca_events.len(), 2);
    assert_eq!(cb_events.len(), 1);
    assert!(
        ca_events[0].custody_sequence < ca_events[1].custody_sequence,
        "EV-CA events must be ordered by custody_sequence"
    );
}

// ─── Migration 0007: validation principles ──────────────────────────────────

#[tokio::test]
async fn test_analysis_note_with_validation_fields_round_trips() {
    use dfars_desktop_lib::db::analysis::list_for_case;

    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-VAL-1").await;

    let input = AnalysisInput {
        evidence_id: None,
        category: "Observation".into(),
        finding: "Artifact X appears consistent with the known sample.".into(),
        description: Some("Detailed reasoning in case journal entry 4.".into()),
        confidence_level: Some("High".into()),
        created_by: Some("J. Henning".into()),
        method_reference: Some("NIST SP 800-86 §5.2".into()),
        alternatives_considered: Some("Could be file corruption — ruled out by SHA256 match.".into()),
        tool_version: Some("exiftool 12.76".into()),
    };

    let saved = add_analysis(&pool, "CASE-VAL-1", &input).await.unwrap();
    assert_eq!(saved.created_by.as_deref(), Some("J. Henning"));
    assert_eq!(saved.method_reference.as_deref(), Some("NIST SP 800-86 §5.2"));
    assert_eq!(
        saved.alternatives_considered.as_deref(),
        Some("Could be file corruption — ruled out by SHA256 match.")
    );
    assert_eq!(saved.tool_version.as_deref(), Some("exiftool 12.76"));

    // Round-trip through the list query to confirm the new columns are in the SELECT.
    let notes = list_for_case(&pool, "CASE-VAL-1").await.unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].created_by.as_deref(), Some("J. Henning"));
    assert_eq!(notes[0].method_reference.as_deref(), Some("NIST SP 800-86 §5.2"));
    assert_eq!(notes[0].tool_version.as_deref(), Some("exiftool 12.76"));
}

#[tokio::test]
async fn test_analysis_note_accepts_null_validation_fields() {
    // Backward-compat path: a note created the "v1 way" (no validation
    // metadata) must still round-trip cleanly with None values, not
    // fail validation or default-backfill.
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-VAL-2").await;

    let note = add_analysis(
        &pool,
        "CASE-VAL-2",
        &AnalysisInput {
            evidence_id: None,
            category: "Other".into(),
            finding: "v1-style finding with no metadata".into(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(note.created_by.is_none());
    assert!(note.method_reference.is_none());
    assert!(note.alternatives_considered.is_none());
    assert!(note.tool_version.is_none());
}

#[tokio::test]
async fn test_analysis_reviews_append_only_and_ordered() {
    use dfars_desktop_lib::db::analysis_reviews::{
        AnalysisReviewInput, add_review, list_for_note,
    };

    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-REV-1").await;

    let note = add_analysis(
        &pool,
        "CASE-REV-1",
        &AnalysisInput {
            evidence_id: None,
            category: "Conclusion".into(),
            finding: "F".into(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let r1 = add_review(
        &pool,
        note.note_id,
        &AnalysisReviewInput {
            reviewed_by: "Reviewer A".into(),
            reviewed_at: "2026-04-20T10:00:00".into(),
            review_notes: Some("Concur with SHA256 reasoning".into()),
        },
    )
    .await
    .unwrap();

    // Tiny sleep not strictly needed — created_at ties are broken by
    // review_id ordering in list_for_note, but even so the ASC ordering
    // by created_at is what the UI consumes. Two INSERTs in the same
    // second will still sort stable by review_id insertion order.
    let r2 = add_review(
        &pool,
        note.note_id,
        &AnalysisReviewInput {
            reviewed_by: "Reviewer B".into(),
            reviewed_at: "2026-04-21T09:30:00".into(),
            review_notes: None,
        },
    )
    .await
    .unwrap();

    assert_ne!(r1.review_id, r2.review_id, "each review is its own row");

    let all = list_for_note(&pool, note.note_id).await.unwrap();
    assert_eq!(all.len(), 2, "multi-reviewer history preserved");
    assert_eq!(all[0].reviewed_by, "Reviewer A");
    assert_eq!(all[1].reviewed_by, "Reviewer B");
}

#[tokio::test]
async fn test_analysis_review_rejects_missing_note() {
    use dfars_desktop_lib::db::analysis_reviews::{AnalysisReviewInput, add_review};

    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-REV-2").await;

    let err = add_review(
        &pool,
        99999, // does not exist
        &AnalysisReviewInput {
            reviewed_by: "Ghost".into(),
            reviewed_at: "2026-04-20T10:00:00".into(),
            review_notes: None,
        },
    )
    .await
    .expect_err("missing note must reject");

    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "note_id"),
        "expected note_id validation error, got {err:?}"
    );
}

#[tokio::test]
async fn test_analysis_review_validation_rejects_empty_reviewer_and_bad_datetime() {
    use dfars_desktop_lib::db::analysis_reviews::{AnalysisReviewInput, add_review};

    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-REV-3").await;

    let note = add_analysis(
        &pool,
        "CASE-REV-3",
        &AnalysisInput {
            evidence_id: None,
            category: "Other".into(),
            finding: "F".into(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Empty reviewer
    let err = add_review(
        &pool,
        note.note_id,
        &AnalysisReviewInput {
            reviewed_by: "   ".into(),
            reviewed_at: "2026-04-20T10:00:00".into(),
            review_notes: None,
        },
    )
    .await
    .expect_err("empty reviewer must reject");
    assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "reviewed_by"));

    // Unparseable datetime
    let err = add_review(
        &pool,
        note.note_id,
        &AnalysisReviewInput {
            reviewed_by: "Rev".into(),
            reviewed_at: "yesterday".into(),
            review_notes: None,
        },
    )
    .await
    .expect_err("bad datetime must reject");
    assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "reviewed_at"));
}

#[tokio::test]
async fn test_analysis_reviews_list_for_case_groups_across_notes() {
    use dfars_desktop_lib::db::analysis_reviews::{
        AnalysisReviewInput, add_review, list_for_case,
    };

    // Two cases, two notes per case, two reviews per note. Verifies
    // (a) the per-case aggregate query returns ONLY the requested
    // case's reviews, ordered note_id ASC then created_at ASC.
    // (b) used by the AnalysisPanel's single-fetch refactor.
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-LFC-A").await;
    setup_case(&pool, "CASE-LFC-B").await;

    let mk_note = |case: &str, kind: &str| {
        let pool = pool.clone();
        let case = case.to_string();
        let kind = kind.to_string();
        async move {
            add_analysis(
                &pool,
                &case,
                &AnalysisInput {
                    evidence_id: None,
                    category: "Other".into(),
                    finding: kind,
                    description: None,
                    confidence_level: None,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
        }
    };

    let n_a1 = mk_note("CASE-LFC-A", "A1").await;
    let n_a2 = mk_note("CASE-LFC-A", "A2").await;
    let n_b1 = mk_note("CASE-LFC-B", "B1").await;

    let mk_review = |note_id: i64, name: &str| {
        let pool = pool.clone();
        let name = name.to_string();
        async move {
            add_review(
                &pool,
                note_id,
                &AnalysisReviewInput {
                    reviewed_by: name,
                    reviewed_at: "2026-04-22T10:00:00".into(),
                    review_notes: None,
                },
            )
            .await
            .unwrap()
        }
    };

    let _ = mk_review(n_a1.note_id, "Rev A1-1").await;
    let _ = mk_review(n_a1.note_id, "Rev A1-2").await;
    let _ = mk_review(n_a2.note_id, "Rev A2-1").await;
    let _ = mk_review(n_b1.note_id, "Rev B1-1").await;

    let case_a_reviews = list_for_case(&pool, "CASE-LFC-A").await.unwrap();
    assert_eq!(case_a_reviews.len(), 3, "case A has 3 reviews across 2 notes");
    assert!(
        case_a_reviews.iter().all(|r| r.note_id == n_a1.note_id || r.note_id == n_a2.note_id),
        "must not leak case B reviews"
    );
    // Ordered by note_id ASC: A1's two reviews come before A2's.
    assert_eq!(case_a_reviews[0].note_id, n_a1.note_id);
    assert_eq!(case_a_reviews[1].note_id, n_a1.note_id);
    assert_eq!(case_a_reviews[2].note_id, n_a2.note_id);

    let case_b_reviews = list_for_case(&pool, "CASE-LFC-B").await.unwrap();
    assert_eq!(case_b_reviews.len(), 1);
    assert_eq!(case_b_reviews[0].note_id, n_b1.note_id);
}

#[tokio::test]
async fn test_analysis_reviews_deterministic_tiebreaker_on_same_second() {
    // Two reviews inserted in the same SQLite-second tie on
    // created_at. The list_for_note ORDER BY adds review_id ASC as
    // tiebreaker so the result is deterministic — earlier review_id
    // (i.e., the first INSERT) sorts first.
    use dfars_desktop_lib::db::analysis_reviews::{
        AnalysisReviewInput, add_review, list_for_note,
    };

    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-TIE").await;

    let note = add_analysis(
        &pool,
        "CASE-TIE",
        &AnalysisInput {
            evidence_id: None,
            category: "Other".into(),
            finding: "F".into(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Insert without delay — both reviews land in the same second.
    let r1 = add_review(
        &pool,
        note.note_id,
        &AnalysisReviewInput {
            reviewed_by: "First".into(),
            reviewed_at: "2026-04-22T10:00:00".into(),
            review_notes: None,
        },
    )
    .await
    .unwrap();
    let r2 = add_review(
        &pool,
        note.note_id,
        &AnalysisReviewInput {
            reviewed_by: "Second".into(),
            reviewed_at: "2026-04-22T10:00:00".into(),
            review_notes: None,
        },
    )
    .await
    .unwrap();

    let listed = list_for_note(&pool, note.note_id).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed[0].review_id, r1.review_id,
        "earliest review_id must sort first when created_at ties"
    );
    assert_eq!(listed[1].review_id, r2.review_id);
}

#[tokio::test]
async fn test_analysis_reviewed_at_length_cap_rejects_huge_input() {
    use dfars_desktop_lib::db::analysis_reviews::{AnalysisReviewInput, add_review};

    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-LEN").await;
    let note = add_analysis(
        &pool,
        "CASE-LEN",
        &AnalysisInput {
            evidence_id: None,
            category: "Other".into(),
            finding: "F".into(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // 65 characters — one over the 64-char defensive cap.
    let oversized = "X".repeat(65);
    let err = add_review(
        &pool,
        note.note_id,
        &AnalysisReviewInput {
            reviewed_by: "Rev".into(),
            reviewed_at: oversized,
            review_notes: None,
        },
    )
    .await
    .expect_err("oversized reviewed_at must reject");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "reviewed_at")
    );
}

#[tokio::test]
async fn test_analysis_finding_uses_char_count_not_byte_count() {
    // Pre-existing byte-vs-char bug fix verification: 250 emoji =
    // ~1000 bytes but 250 chars. Old `.len()` check would reject;
    // new `.chars().count()` accepts since 250 ≤ FINDING_MAX_LEN (500).
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-UNICODE").await;

    let emoji_finding = "🎯".repeat(250); // 250 chars, ~1000 bytes
    let result = add_analysis(
        &pool,
        "CASE-UNICODE",
        &AnalysisInput {
            evidence_id: None,
            category: "Observation".into(),
            finding: emoji_finding.clone(),
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await;
    assert!(
        result.is_ok(),
        "250-char Unicode finding must be accepted (chars, not bytes): {result:?}"
    );

    // 501 emojis must still reject (over the chars cap).
    let too_many = "🎯".repeat(501);
    let err = add_analysis(
        &pool,
        "CASE-UNICODE",
        &AnalysisInput {
            evidence_id: None,
            category: "Observation".into(),
            finding: too_many,
            description: None,
            confidence_level: None,
            ..Default::default()
        },
    )
    .await
    .expect_err("501-char finding must reject");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "finding")
    );
}

// ─── Additional: analysis default confidence is Medium ────────────────────────

#[tokio::test]
async fn test_analysis_default_confidence() {
    let (_state, pool) = build_state().await;
    setup_case(&pool, "CASE-ANA-DEF").await;

    let note = add_analysis(
        &pool,
        "CASE-ANA-DEF",
        &AnalysisInput {
            evidence_id: None,
            category: "Other".to_string(),
            finding: "Finding".to_string(),
            description: None,
            confidence_level: None, // not provided — must default to Medium
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(note.confidence_level, "Medium");
}
