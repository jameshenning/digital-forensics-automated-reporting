pub mod analysis;
pub mod analysis_reviews;
pub mod cases;
pub mod custody;
pub mod entities;
pub mod events;
pub mod evidence;
pub mod evidence_files;
pub mod graph;
pub mod inspector;
pub mod hashes;
pub mod links;
pub mod person_employers;
pub mod person_identifiers;
pub mod business_identifiers;
pub mod tools;

use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, SqlitePool};
use std::path::Path;

/// Holds the two connection pools — one per SQLite file.
/// Matches v1's two-DB layout: forensics.db (case data) and auth.db (credentials).
pub struct AppDb {
    /// forensics pool is used by Phase 2+ commands (cases, evidence, etc.)
    pub forensics: SqlitePool,
    pub auth: SqlitePool,
}

/// Open (or create) a single SQLite pool and run the given embedded migrations.
async fn open_pool(db_path: &Path, migrator: sqlx::migrate::Migrator) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;

    migrator.run(&pool).await?;

    Ok(pool)
}

/// Initialize both DB pools and apply all pending migrations.
/// Called once at app startup inside the `.setup()` closure.
pub async fn init(forensics_path: &Path, auth_path: &Path) -> Result<AppDb, sqlx::Error> {
    let forensics_migrator = sqlx::migrate!("./migrations/forensics");
    let auth_migrator = sqlx::migrate!("./migrations/auth");

    let forensics = open_pool(forensics_path, forensics_migrator).await?;
    let auth = open_pool(auth_path, auth_migrator).await?;

    // Idempotent runtime schema guard: ensure `tool_usage.evidence_id` exists.
    //
    // v1 added this column via runtime ALTER TABLE in app/database.py. It was
    // not in the original schema file, so the Phase 3a agent added a separate
    // 0002_tool_evidence_id.sql migration. That migration uses ALTER TABLE ADD
    // COLUMN — which SQLite does NOT support with IF NOT EXISTS, so it fails
    // with "duplicate column" on any v1 database that already has the column
    // from v1's own ALTER. sqlx panics on migration failure, crashing the app.
    //
    // Fix: the migration file has been removed; this block runs after the
    // remaining migrations and ensures the column exists via PRAGMA + dynamic
    // ALTER. Idempotent and works on both fresh installs and v1 upgrades.
    ensure_tool_evidence_id_column(&forensics).await?;

    Ok(AppDb { forensics, auth })
}

/// Check whether `tool_usage.evidence_id` exists; add it + index if missing.
/// Idempotent — safe to call on every startup.
async fn ensure_tool_evidence_id_column(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('tool_usage')")
        .fetch_all(pool)
        .await?;

    if !cols.iter().any(|c| c == "evidence_id") {
        sqlx::query("ALTER TABLE tool_usage ADD COLUMN evidence_id TEXT")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tool_evidence_id ON tool_usage(evidence_id)")
            .execute(pool)
            .await?;
    }
    Ok(())
}
