/// Phase 2 Cases Integration Tests
///
/// Covers all 9 test families specified in the Phase 2 implementation brief:
///   1. CRUD roundtrip (create → list → get → update → list → delete → list)
///   2. Duplicate case_id on create → CaseAlreadyExists
///   3. Update non-existent case_id → CaseNotFound
///   4. Delete non-existent case_id → CaseNotFound
///   5. Delete case with evidence → CaseHasEvidence
///   6. Tag lifecycle (dedup, update, sort)
///   7. Validation failures (case_id chars, status allowlist, priority allowlist)
///   8. Session guard — each command with empty/invalid token → Unauthorized
///   9. v1 compat proof — row inserted by v2 readable in v1's column order
///
/// Run: `cargo test --test phase2_cases_integration`

use chrono::NaiveDate;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

use dfars_desktop_lib::{
    auth::{argon, lockout::LockoutMap, session::SessionState},
    crypto::CryptoState,
    db::{
        AppDb,
        cases::{CaseInput, create_case, delete_case, get_case, list_cases, update_case},
    },
    error::AppError,
    state::AppState,
};

use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

/// Monotonically increasing counter so each test gets a unique in-memory DB name.
static DB_COUNTER: AtomicU64 = AtomicU64::new(1);

// ─── Schema constants ─────────────────────────────────────────────────────────

// Full forensics DDL (verbatim from the migration file).
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

/// Open a uniquely-named in-memory SQLite pool with the given DDL applied.
///
/// Each call gets its own isolated database — no cross-test state sharing.
/// We use a named in-memory URI (`file:dfars_test_N?mode=memory&cache=shared`)
/// so that the SQLite driver treats it as a separate private database.
async fn make_pool(ddl: &str) -> SqlitePool {
    let id = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let uri = format!("file:dfars_test_{id}?mode=memory&cache=shared");

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

/// Build an AppState with both auth and forensics pools fully schema-migrated.
/// Returns `(Arc<AppState>, forensics_pool)`.
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

/// Build a minimal CaseInput with required fields set; optional fields are None.
fn minimal_input(case_id: &str) -> CaseInput {
    CaseInput {
        case_id: case_id.to_string(),
        case_name: format!("Test Case {case_id}"),
        description: None,
        investigator: "examiner".to_string(),
        agency: None,
        start_date: NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
        end_date: None,
        status: None,   // defaults to "Active"
        priority: None, // defaults to "Medium"
        classification: None,
        evidence_drive_path: None,
        tags: vec![],
    }
}

// ─── Test 1: CRUD roundtrip ───────────────────────────────────────────────────

#[tokio::test]
async fn test_01_crud_roundtrip() {
    let (_state, pool) = build_state().await;

    // Create
    let input = CaseInput {
        case_id: "CASE-2026-001".to_string(),
        case_name: "Roundtrip Test".to_string(),
        description: Some("desc".to_string()),
        investigator: "alice".to_string(),
        agency: Some("FBI".to_string()),
        start_date: NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
        end_date: None,
        status: Some("Active".to_string()),
        priority: Some("High".to_string()),
        classification: Some("Confidential".to_string()),
        evidence_drive_path: Some("E:\\".to_string()),
        tags: vec!["cyber".to_string(), "fraud".to_string()],
    };
    let created = create_case(&pool, &input).await.expect("create_case failed");
    assert_eq!(created.case.case_id, "CASE-2026-001");
    assert_eq!(created.case.status, "Active");
    assert_eq!(created.case.priority, "High");
    assert_eq!(created.tags, vec!["cyber", "fraud"]);

    // List — should show 1 row
    let list = list_cases(&pool, 100, 0).await.expect("list_cases failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].case_id, "CASE-2026-001");
    assert_eq!(list[0].evidence_count, 0);

    // Get
    let detail = get_case(&pool, "CASE-2026-001").await.expect("get_case failed");
    assert_eq!(detail.case.investigator, "alice");
    assert_eq!(detail.case.agency.as_deref(), Some("FBI"));
    assert_eq!(detail.tags, vec!["cyber", "fraud"]);

    // Update
    let update_input = CaseInput {
        case_id: "CASE-2026-001".to_string(),
        case_name: "Roundtrip Test UPDATED".to_string(),
        description: Some("updated desc".to_string()),
        investigator: "alice".to_string(),
        agency: None,
        start_date: NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
        end_date: Some(NaiveDate::from_ymd_opt(2026, 4, 1).unwrap()),
        status: Some("Closed".to_string()),
        priority: Some("Medium".to_string()),
        classification: None,
        evidence_drive_path: None,
        tags: vec!["closed".to_string()],
    };
    let updated = update_case(&pool, "CASE-2026-001", &update_input)
        .await
        .expect("update_case failed");
    assert_eq!(updated.case.case_name, "Roundtrip Test UPDATED");
    assert_eq!(updated.case.status, "Closed");
    assert_eq!(updated.tags, vec!["closed"]);

    // List again — still 1 row, name is updated
    let list2 = list_cases(&pool, 100, 0).await.expect("list_cases failed");
    assert_eq!(list2.len(), 1);
    assert_eq!(list2[0].case_id, "CASE-2026-001");

    // Delete
    delete_case(&pool, "CASE-2026-001").await.expect("delete_case failed");

    // List — empty
    let list3 = list_cases(&pool, 100, 0).await.expect("list_cases after delete");
    assert!(list3.is_empty(), "list should be empty after delete");
}

// ─── Test 2: Duplicate case_id → CaseAlreadyExists ───────────────────────────

#[tokio::test]
async fn test_02_duplicate_case_id() {
    let (_state, pool) = build_state().await;

    let input = minimal_input("DUP-001");
    create_case(&pool, &input).await.expect("first create must succeed");

    let err = create_case(&pool, &input).await.expect_err("second create must fail");
    assert!(
        matches!(err, AppError::CaseAlreadyExists { ref case_id } if case_id == "DUP-001"),
        "expected CaseAlreadyExists, got: {err:?}"
    );
}

// ─── Test 3: Update non-existent case_id → CaseNotFound ──────────────────────

#[tokio::test]
async fn test_03_update_nonexistent() {
    let (_state, pool) = build_state().await;

    let input = minimal_input("GHOST-001");
    let err = update_case(&pool, "GHOST-001", &input)
        .await
        .expect_err("update of missing case must fail");
    assert!(
        matches!(err, AppError::CaseNotFound { ref case_id } if case_id == "GHOST-001"),
        "expected CaseNotFound, got: {err:?}"
    );
}

// ─── Test 4: Delete non-existent case_id → CaseNotFound ──────────────────────

#[tokio::test]
async fn test_04_delete_nonexistent() {
    let (_state, pool) = build_state().await;

    let err = delete_case(&pool, "GHOST-002")
        .await
        .expect_err("delete of missing case must fail");
    assert!(
        matches!(err, AppError::CaseNotFound { ref case_id } if case_id == "GHOST-002"),
        "expected CaseNotFound, got: {err:?}"
    );
}

// ─── Test 5: Delete case with evidence → CaseHasEvidence ─────────────────────

#[tokio::test]
async fn test_05_delete_case_with_evidence() {
    let (_state, pool) = build_state().await;

    // Create the case first
    let input = minimal_input("CASE-WITH-EVIDENCE");
    create_case(&pool, &input).await.expect("create_case");

    // Insert an evidence row directly (bypassing Phase 2 CRUD — evidence is Phase 3).
    // This exercises the FK RESTRICT path.
    sqlx::query(
        r#"
        INSERT INTO evidence (
            evidence_id, case_id, description, collected_by, collection_datetime
        ) VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind("EV-001")
    .bind("CASE-WITH-EVIDENCE")
    .bind("Test evidence item")
    .bind("examiner")
    .bind("2026-04-12T10:00:00")
    .execute(&pool)
    .await
    .expect("insert evidence for test");

    // Now attempt to delete the case — must fail with CaseHasEvidence
    let err = delete_case(&pool, "CASE-WITH-EVIDENCE")
        .await
        .expect_err("delete must fail when evidence exists");
    assert!(
        matches!(err, AppError::CaseHasEvidence { ref case_id } if case_id == "CASE-WITH-EVIDENCE"),
        "expected CaseHasEvidence, got: {err:?}"
    );
}

// ─── Test 6: Tag lifecycle ────────────────────────────────────────────────────

#[tokio::test]
async fn test_06_tag_lifecycle() {
    let (_state, pool) = build_state().await;

    // Create with duplicate tags
    let mut input = minimal_input("TAG-CASE");
    input.tags = vec![
        "urgent".to_string(),
        "cyber".to_string(),
        "URGENT".to_string(), // should dedup with "urgent"
        "  Cyber  ".to_string(), // should dedup after trim+lower
    ];
    let created = create_case(&pool, &input).await.expect("create");

    // Should be deduped and sorted
    assert_eq!(
        created.tags,
        vec!["cyber", "urgent"],
        "tags must be deduped and sorted: got {:?}",
        created.tags
    );

    // List view shouldn't show tags (CaseSummary doesn't carry them)
    let list = list_cases(&pool, 100, 0).await.unwrap();
    assert_eq!(list.len(), 1);

    // Get — sorted
    let detail = get_case(&pool, "TAG-CASE").await.unwrap();
    assert_eq!(detail.tags, vec!["cyber", "urgent"]);

    // Update — replace tags completely
    let mut update = minimal_input("TAG-CASE");
    update.tags = vec!["closed".to_string()];
    let updated = update_case(&pool, "TAG-CASE", &update).await.unwrap();
    assert_eq!(updated.tags, vec!["closed"], "old tags must be gone");

    // Get after update — old tags gone, new tag present
    let detail2 = get_case(&pool, "TAG-CASE").await.unwrap();
    assert_eq!(detail2.tags, vec!["closed"]);
    assert!(!detail2.tags.contains(&"cyber".to_string()));
}

// ─── Test 7: Validation failures ─────────────────────────────────────────────

#[tokio::test]
async fn test_07a_invalid_case_id_chars() {
    let (_state, pool) = build_state().await;

    // case_id with a space — not in allowlist
    let mut input = minimal_input("CASE 001");
    input.case_id = "CASE 001".to_string();
    let err = create_case(&pool, &input).await.expect_err("space in case_id must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "case_id"),
        "expected ValidationError on case_id, got: {err:?}"
    );
}

#[tokio::test]
async fn test_07b_invalid_status() {
    let (_state, pool) = build_state().await;

    let mut input = minimal_input("STATUS-TEST");
    input.status = Some("Deleted".to_string()); // not in allowlist
    let err = create_case(&pool, &input).await.expect_err("invalid status must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "status"),
        "expected ValidationError on status, got: {err:?}"
    );
}

#[tokio::test]
async fn test_07c_invalid_priority() {
    let (_state, pool) = build_state().await;

    let mut input = minimal_input("PRIORITY-TEST");
    input.priority = Some("Urgent".to_string()); // not in allowlist
    let err = create_case(&pool, &input).await.expect_err("invalid priority must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "priority"),
        "expected ValidationError on priority, got: {err:?}"
    );
}

#[tokio::test]
async fn test_07d_empty_case_id() {
    let (_state, pool) = build_state().await;

    let mut input = minimal_input("");
    input.case_id = "".to_string();
    let err = create_case(&pool, &input).await.expect_err("empty case_id must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "case_id"),
        "expected ValidationError on case_id, got: {err:?}"
    );
}

#[tokio::test]
async fn test_07e_case_id_too_long() {
    let (_state, pool) = build_state().await;

    let long_id = "A".repeat(65);
    let mut input = minimal_input(&long_id);
    input.case_id = long_id;
    let err = create_case(&pool, &input).await.expect_err("too-long case_id must fail");
    assert!(
        matches!(err, AppError::ValidationError { ref field, .. } if field == "case_id"),
        "expected ValidationError on case_id length, got: {err:?}"
    );
}

// ─── Test 8: Session guard — commands require valid session ───────────────────
//
// These tests exercise the Tauri command layer through the AppState session map.
// We call the db query layer directly to verify DB logic, but also test that
// `require_session` rejects bad tokens.

#[tokio::test]
async fn test_08_session_guard_empty_token() {
    use dfars_desktop_lib::auth::session::require_session;

    let (state, _pool) = build_state().await;

    // Empty token — no session exists
    let err = require_session(&state, "").expect_err("empty token must be rejected");
    assert!(
        matches!(err, AppError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );
}

#[tokio::test]
async fn test_08_session_guard_invalid_token() {
    use dfars_desktop_lib::auth::session::require_session;

    let (state, _pool) = build_state().await;

    // Random invalid token
    let err = require_session(&state, "sess_thisisnotavalidtoken00000000000")
        .expect_err("invalid token must be rejected");
    assert!(
        matches!(err, AppError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );
}

#[tokio::test]
async fn test_08_session_guard_pending_session_rejected() {
    use dfars_desktop_lib::auth::session::require_session;

    let (state, _pool) = build_state().await;

    // Create a pending (MFA-incomplete) session — must NOT pass require_session
    let token = state.sessions.create_pending("alice", None);
    let err = require_session(&state, &token)
        .expect_err("pending session must be rejected by require_session");
    assert!(
        matches!(err, AppError::MfaRequired),
        "expected MfaRequired for pending session, got: {err:?}"
    );
}

#[tokio::test]
async fn test_08_session_guard_verified_session_accepted() {
    use dfars_desktop_lib::auth::session::require_session;

    let (state, _pool) = build_state().await;

    // A verified session must be accepted
    let token = state.sessions.create_verified("alice");
    let session_data = require_session(&state, &token).expect("verified session must be accepted");
    assert_eq!(session_data.username, "alice");
}

// ─── Test 9: v1 compat proof ──────────────────────────────────────────────────
//
// Insert a case using v2's create_case. Then read it back using a raw SELECT
// in the exact column order that v1's `SELECT * FROM cases WHERE case_id = ?`
// would return (Python sqlite3 with row_factory=sqlite3.Row + dict(row) maps
// columns by name, so any order works — but the important test is that the
// column *values* survive round-trip unchanged).

#[tokio::test]
async fn test_09_v1_compat_proof() {
    let (_state, pool) = build_state().await;

    let input = CaseInput {
        case_id: "V1-COMPAT-001".to_string(),
        case_name: "V1 Compat Test".to_string(),
        description: Some("Testing v1/v2 compat".to_string()),
        investigator: "investigator1".to_string(),
        agency: Some("DFARS Lab".to_string()),
        start_date: NaiveDate::from_ymd_opt(2026, 4, 12).unwrap(),
        end_date: None,
        status: Some("Active".to_string()),
        priority: Some("High".to_string()),
        classification: Some("Unclassified".to_string()),
        evidence_drive_path: Some("D:\\Evidence\\".to_string()),
        tags: vec!["v1-compat".to_string()],
    };

    create_case(&pool, &input).await.expect("create for v1 compat test");

    // Mimic v1's exact SELECT * column order from database.py get_case():
    // case_id, case_name, description, investigator, agency,
    // start_date, end_date, status, priority, classification,
    // evidence_drive_path, created_at, updated_at
    let row: (
        String, // case_id
        String, // case_name
        Option<String>, // description
        String, // investigator
        Option<String>, // agency
        String, // start_date (SQLite DATE stored as TEXT)
        Option<String>, // end_date
        String, // status
        String, // priority
        Option<String>, // classification
        Option<String>, // evidence_drive_path
        String, // created_at
        String, // updated_at
    ) = sqlx::query_as(
        r#"
        SELECT case_id, case_name, description, investigator, agency,
               start_date, end_date, status, priority, classification,
               evidence_drive_path, created_at, updated_at
        FROM cases WHERE case_id = ?
        "#,
    )
    .bind("V1-COMPAT-001")
    .fetch_one(&pool)
    .await
    .expect("v1 compat SELECT failed");

    // Values inserted by v2 must read back identically.
    assert_eq!(row.0, "V1-COMPAT-001", "case_id mismatch");
    assert_eq!(row.1, "V1 Compat Test", "case_name mismatch");
    assert_eq!(row.2.as_deref(), Some("Testing v1/v2 compat"), "description mismatch");
    assert_eq!(row.3, "investigator1", "investigator mismatch");
    assert_eq!(row.4.as_deref(), Some("DFARS Lab"), "agency mismatch");
    assert_eq!(row.5, "2026-04-12", "start_date must be stored as ISO date string");
    assert!(row.6.is_none(), "end_date must be NULL");
    assert_eq!(row.7, "Active", "status mismatch");
    assert_eq!(row.8, "High", "priority mismatch");
    assert_eq!(row.9.as_deref(), Some("Unclassified"), "classification mismatch");
    assert_eq!(row.10.as_deref(), Some("D:\\Evidence\\"), "evidence_drive_path mismatch");
    // created_at and updated_at are CURRENT_TIMESTAMP — just check they're non-empty
    assert!(!row.11.is_empty(), "created_at must not be empty");
    assert!(!row.12.is_empty(), "updated_at must not be empty");

    // Tags round-trip: inserted by v2, should be readable by a simple SELECT
    let tag_rows: Vec<(String,)> =
        sqlx::query_as("SELECT tag FROM case_tags WHERE case_id = ? ORDER BY tag")
            .bind("V1-COMPAT-001")
            .fetch_all(&pool)
            .await
            .expect("tag SELECT failed");
    let tags: Vec<&str> = tag_rows.iter().map(|(t,)| t.as_str()).collect();
    assert_eq!(tags, vec!["v1-compat"], "tag must survive round-trip");
}

// ─── Test: pagination ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_pagination() {
    let (_state, pool) = build_state().await;

    // Insert 5 cases
    for i in 1..=5 {
        let input = minimal_input(&format!("PAGED-{i:03}"));
        create_case(&pool, &input).await.unwrap();
    }

    // limit=2 offset=0 — first 2
    let page1 = list_cases(&pool, 2, 0).await.unwrap();
    assert_eq!(page1.len(), 2);

    // limit=2 offset=2 — next 2
    let page2 = list_cases(&pool, 2, 2).await.unwrap();
    assert_eq!(page2.len(), 2);

    // limit=2 offset=4 — last 1
    let page3 = list_cases(&pool, 2, 4).await.unwrap();
    assert_eq!(page3.len(), 1);

    // All 5 IDs across pages should be distinct
    let all_ids: std::collections::HashSet<_> = page1
        .iter()
        .chain(page2.iter())
        .chain(page3.iter())
        .map(|c| &c.case_id)
        .collect();
    assert_eq!(all_ids.len(), 5);
}

// ─── Test: evidence_count aggregation ────────────────────────────────────────

#[tokio::test]
async fn test_evidence_count_in_list() {
    let (_state, pool) = build_state().await;

    create_case(&pool, &minimal_input("EC-001")).await.unwrap();

    // Insert 3 evidence rows directly
    for i in 1..=3 {
        sqlx::query(
            r#"
            INSERT INTO evidence (
                evidence_id, case_id, description, collected_by, collection_datetime
            ) VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(format!("EV-EC-{i}"))
        .bind("EC-001")
        .bind(format!("Evidence item {i}"))
        .bind("examiner")
        .bind("2026-04-12T10:00:00")
        .execute(&pool)
        .await
        .unwrap();
    }

    let list = list_cases(&pool, 100, 0).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        list[0].evidence_count, 3,
        "evidence_count must reflect 3 inserted rows"
    );
}

// ─── Test: all valid status values ───────────────────────────────────────────

#[tokio::test]
async fn test_all_valid_statuses() {
    let (_state, pool) = build_state().await;

    for (i, status) in ["Active", "Closed", "Pending", "Archived"].iter().enumerate() {
        let mut input = minimal_input(&format!("STATUS-{i}"));
        input.status = Some(status.to_string());
        let detail = create_case(&pool, &input).await.unwrap_or_else(|e| {
            panic!("status '{status}' must be valid, got: {e:?}")
        });
        assert_eq!(detail.case.status, *status);
    }
}

// ─── Test: all valid priority values ─────────────────────────────────────────

#[tokio::test]
async fn test_all_valid_priorities() {
    let (_state, pool) = build_state().await;

    for (i, priority) in ["Low", "Medium", "High", "Critical"].iter().enumerate() {
        let mut input = minimal_input(&format!("PRIO-{i}"));
        input.priority = Some(priority.to_string());
        let detail = create_case(&pool, &input).await.unwrap_or_else(|e| {
            panic!("priority '{priority}' must be valid, got: {e:?}")
        });
        assert_eq!(detail.case.priority, *priority);
    }
}
