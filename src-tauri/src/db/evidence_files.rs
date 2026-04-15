/// Evidence files database queries — Phase 3b.
///
/// Manages the `evidence_files` table: insert, get, list, soft-delete, purge.
///
/// Public surface:
///   - `insert_file`       — INSERT a new row after the file has been written to disk
///   - `get_file`          — fetch single row by file_id
///   - `list_for_evidence` — all non-deleted files for an evidence item
///   - `soft_delete_file`  — flip is_deleted = 1; disk file is NOT unlinked
///   - `purge_file`        — DELETE the DB row; caller must have already unlinked disk
///
/// All queries use dynamic `sqlx::query(...)/.bind(...)` — no `query!` macros.
// NaiveDateTime no longer needed — `uploaded_at` is a String for v1 compat.
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full `evidence_files` row, maps 1:1 to the table schema.
/// `uploaded_at` is a `String` for v1 compat — see `db::cases::Case`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EvidenceFile {
    pub file_id: i64,
    pub evidence_id: String,
    pub original_filename: String,
    pub stored_path: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub mime_type: Option<String>,
    pub metadata_json: Option<String>,
    pub is_deleted: i64,
    pub uploaded_at: String,
}

/// Return value for the download command.
///
/// `hash_verified` is set by the caller (uploads.rs) after re-hashing the
/// stored file on every download call (SEC-3 MUST-DO 4).
/// `is_executable` is set by MIME/magic-byte sniffing (SEC-3 SHOULD-DO 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFileDownload {
    /// Absolute path to the stored file on disk (serialised as a plain string
    /// so the frontend receives a JSON string, not the array-of-components
    /// that serde produces from PathBuf on Windows).
    pub path: String,
    /// True if the re-computed SHA-256 matches the DB-stored value.
    pub hash_verified: bool,
    /// True if the file's magic bytes indicate a PE/ELF/Mach-O/script.
    pub is_executable: bool,
    /// Original filename — useful for "Save As" defaults in the frontend.
    pub original_filename: String,
}

// ─── DB operations ────────────────────────────────────────────────────────────

/// Insert a new evidence file row.  Called after the file has been written to
/// disk and the SHA-256 has been computed in the single-pass streaming write.
///
/// Returns the `file_id` assigned by the DB (used as part of the on-disk name).
pub async fn insert_file(
    pool: &SqlitePool,
    evidence_id: &str,
    original_filename: &str,
    stored_path: &str,
    sha256: &str,
    size_bytes: i64,
    mime_type: Option<&str>,
    metadata_json: Option<&str>,
) -> Result<i64, AppError> {
    let row = sqlx::query(
        r#"
        INSERT INTO evidence_files
            (evidence_id, original_filename, stored_path, sha256, size_bytes,
             mime_type, metadata_json, is_deleted)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        RETURNING file_id
        "#,
    )
    .bind(evidence_id)
    .bind(original_filename)
    .bind(stored_path)
    .bind(sha256)
    .bind(size_bytes)
    .bind(mime_type)
    .bind(metadata_json)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;

    let file_id: i64 = row.try_get(0).map_err(AppError::from)?;
    Ok(file_id)
}

/// Fetch a single file row by file_id.
/// Returns `AppError::EvidenceFileNotFound` if the row doesn't exist.
pub async fn get_file(pool: &SqlitePool, file_id: i64) -> Result<EvidenceFile, AppError> {
    sqlx::query_as::<_, EvidenceFile>(
        r#"
        SELECT file_id, evidence_id, original_filename, stored_path, sha256,
               size_bytes, mime_type, metadata_json, is_deleted, uploaded_at
        FROM evidence_files
        WHERE file_id = ?
        "#,
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::EvidenceFileNotFound { file_id })
}

/// List all non-deleted files for a given evidence item.
/// Returns an empty Vec if the evidence_id has no files.
pub async fn list_for_evidence(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<Vec<EvidenceFile>, AppError> {
    sqlx::query_as::<_, EvidenceFile>(
        r#"
        SELECT file_id, evidence_id, original_filename, stored_path, sha256,
               size_bytes, mime_type, metadata_json, is_deleted, uploaded_at
        FROM evidence_files
        WHERE evidence_id = ? AND is_deleted = 0
        ORDER BY uploaded_at ASC
        "#,
    )
    .bind(evidence_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Soft-delete: flip `is_deleted = 1`. Disk file is NOT unlinked.
/// Returns `EvidenceFileNotFound` if the row doesn't exist.
pub async fn soft_delete_file(pool: &SqlitePool, file_id: i64) -> Result<(), AppError> {
    let rows = sqlx::query(
        "UPDATE evidence_files SET is_deleted = 1 WHERE file_id = ?",
    )
    .bind(file_id)
    .execute(pool)
    .await
    .map_err(AppError::from)?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::EvidenceFileNotFound { file_id });
    }
    Ok(())
}

/// Hard-delete: remove the DB row.
/// Disk file must already be unlinked by the caller (`uploads::purge_file`).
/// Returns `EvidenceFileNotFound` if the row doesn't exist.
pub async fn purge_file(pool: &SqlitePool, file_id: i64) -> Result<(), AppError> {
    let rows = sqlx::query("DELETE FROM evidence_files WHERE file_id = ?")
        .bind(file_id)
        .execute(pool)
        .await
        .map_err(AppError::from)?
        .rows_affected();

    if rows == 0 {
        return Err(AppError::EvidenceFileNotFound { file_id });
    }
    Ok(())
}

// ─── Helper to use with sqlx::Row ────────────────────────────────────────────

use sqlx::Row;
