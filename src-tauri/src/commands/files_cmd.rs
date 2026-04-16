/// Evidence file Tauri commands — Phase 3b.
///
/// MUST-DO 3 (SEC-1): every command starts with `require_session()`.
///
/// Commands:
///   - `evidence_files_upload`        — streaming SHA-256 + write, SEC-3 compliant
///   - `evidence_files_list`          — list non-deleted files for an evidence item
///   - `evidence_files_download`      — re-hash on every call (MUST-DO 4)
///   - `evidence_files_soft_delete`   — flip is_deleted flag
///   - `evidence_files_purge`         — hard-delete with mandatory justification
///   - `settings_acknowledge_onedrive_risk` — clears the OneDrive warning
///
/// Storage layout (MUST-DO 1):
///   With evidence_drive_path: `<drive>/DFARS_Evidence/<case_id>/<evidence_id>/`
///   Fallback:                 `%APPDATA%\DFARS\evidence_files\<case_id>/<evidence_id>/`
use std::{path::Path, sync::Arc};

use serde::Serialize;
use tauri::State;
use tracing::info;

use crate::{
    audit,
    auth::session::require_session,
    db::{
        entities,
        evidence_files::{EvidenceFile, EvidenceFileDownload},
    },
    error::AppError,
    state::AppState,
    uploads::{self, DEFAULT_MAX_UPLOAD_BYTES},
};

// ─── Helper: resolve appdata root ─────────────────────────────────────────────

fn appdata_root() -> std::path::PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

// ─── Upload ───────────────────────────────────────────────────────────────────

/// Upload response — includes the file row plus an optional soft-limit warning.
#[derive(Debug, Serialize)]
pub struct EvidenceFileUploadResponse {
    #[serde(flatten)]
    pub file: EvidenceFile,
    /// Non-empty if the file exceeds the 2 GiB soft warning threshold.
    pub warning: Option<String>,
}

/// Upload a single file from `source_path` to the evidence storage tree.
///
/// Returns the completed `EvidenceFile` row.  The `warning` field is non-empty
/// if the file is between 2 GiB and 50 GiB.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_files_upload(
    token: String,
    evidence_id: String,
    source_path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<EvidenceFileUploadResponse, AppError> {
    // MUST-DO 3 (SEC-1): session guard is the first call
    let session = require_session(&state, &token)?;

    let max_bytes = DEFAULT_MAX_UPLOAD_BYTES;
    let appdata = appdata_root();

    let result = uploads::upload_file(
        &state,
        &evidence_id,
        Path::new(&source_path),
        &session.username,
        max_bytes,
        &appdata,
    )
    .await?;

    info!(
        username = %session.username,
        evidence_id = %evidence_id,
        file_id = result.file.file_id,
        "evidence file uploaded"
    );

    Ok(EvidenceFileUploadResponse {
        file: result.file,
        warning: result.warning,
    })
}

// ─── List ─────────────────────────────────────────────────────────────────────

/// List all non-deleted files for a given evidence item.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_files_list(
    token: String,
    evidence_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<EvidenceFile>, AppError> {
    let _session = require_session(&state, &token)?;

    crate::db::evidence_files::list_for_evidence(&state.db.forensics, &evidence_id).await
}

// ─── Download ─────────────────────────────────────────────────────────────────

/// Download: re-hash the stored file on every call (MUST-DO 4).
///
/// Returns `EvidenceFileDownload { path, hash_verified, is_executable, original_filename }`.
/// If `hash_verified = false`, an ERROR-severity audit entry has already been written
/// by `uploads::download_file`.  The frontend must surface an integrity warning.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_files_download(
    token: String,
    file_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<EvidenceFileDownload, AppError> {
    let session = require_session(&state, &token)?;

    uploads::download_file(&state, file_id, &session.username).await
}

// ─── Soft delete ──────────────────────────────────────────────────────────────

/// Soft-delete: flip `is_deleted = 1`.  Disk file is NOT unlinked.
/// Use `evidence_files_purge` for a justified, hard-delete with disk unlink.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_files_soft_delete(
    token: String,
    file_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    // Fetch the file to get evidence_id for audit
    let file_row = crate::db::evidence_files::get_file(&state.db.forensics, file_id).await?;
    let ev = crate::db::evidence::get_evidence(&state.db.forensics, &file_row.evidence_id).await?;

    crate::db::evidence_files::soft_delete_file(&state.db.forensics, file_id).await?;

    audit::log_case(
        &ev.case_id,
        &session.username,
        audit::FILE_SOFT_DELETED,
        &format!(
            "file_id={file_id} evidence_id={} original_filename=\"{}\" sha256={}",
            file_row.evidence_id,
            file_row.original_filename,
            file_row.sha256,
        ),
    );

    info!(
        username = %session.username,
        file_id = file_id,
        "evidence file soft-deleted"
    );

    Ok(())
}

// ─── Purge ────────────────────────────────────────────────────────────────────

/// Purge: hard-delete the disk file + DB row with a mandatory justification.
///
/// Audit entry at WARN severity includes the full SHA-256 and justification.
/// Returns `ValidationError` if justification is empty.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_files_purge(
    token: String,
    file_id: i64,
    justification: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    uploads::purge_file(&state, file_id, &justification, &session.username).await
}

// ─── OneDrive acknowledgment ──────────────────────────────────────────────────

/// Acknowledge the OneDrive sync risk.
///
/// Writes an audit log entry confirming the investigator acknowledged the risk.
/// In a full implementation this would also flip a `onedrive_risk_acknowledged`
/// bit in `config.json` so the warning fires exactly once per install.
#[tauri::command(rename_all = "snake_case")]
pub async fn settings_acknowledge_onedrive_risk(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    // Audit the acknowledgment (required by SEC-3 MUST-DO 5)
    audit::log_auth(
        &session.username,
        audit::ONEDRIVE_WARNING_ACKNOWLEDGED,
        "Investigator acknowledged OneDrive sync risk for evidence files storage",
    );

    info!(
        username = %session.username,
        "OneDrive sync risk acknowledged"
    );

    Ok(())
}

// ─── Person photo upload (migration 0002 — Persons feature) ──────────────────
//
// Not SEC-3 gated. Photos are identifying metadata, not chain-of-custody
// evidence. Lives under %APPDATA%\DFARS\person_photos\ separate from the
// evidence tree.

/// Upload a photo for a person entity. Validates that the entity exists and
/// is a person, copies the photo into the person-photo tree, and updates the
/// entity's `photo_path` column. Returns the updated photo_path so the
/// frontend can render it via `convertFileSrc()`.
#[tauri::command(rename_all = "snake_case")]
pub async fn person_photo_upload(
    token: String,
    entity_id: i64,
    source_path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let session = require_session(&state, &token)?;

    // Verify the entity exists and is a person
    let entity = entities::get_entity(&state.db.forensics, entity_id).await?;
    if entity.is_deleted != 0 {
        return Err(AppError::EntityNotFound { entity_id });
    }
    if entity.entity_type != "person" {
        return Err(AppError::EntityNotAPerson {
            entity_id,
            entity_type: entity.entity_type.clone(),
        });
    }

    // Copy the photo to the person-photo tree
    let appdata = appdata_root();
    let stored_path = uploads::upload_person_photo(&source_path, &entity.case_id, entity_id, &appdata)?;
    let stored_str = stored_path.to_string_lossy().into_owned();

    // Update the entity row with the new photo_path. We go through a direct
    // UPDATE because entity_update would also require re-validating all the
    // other fields — we only want to touch photo_path here.
    sqlx::query("UPDATE entities SET photo_path = ?, updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?")
        .bind(&stored_str)
        .bind(entity_id)
        .execute(&state.db.forensics)
        .await
        .map_err(AppError::from)?;

    info!(
        username = %session.username,
        entity_id = entity_id,
        "person photo uploaded"
    );

    Ok(stored_str)
}

// ─── file_compute_sha256 (Reproducibility feature) ───────────────────────────
//
// Read-only utility that computes the SHA-256 of a file at a given path.
// Used by the Tool form's "Compute Hash" button to populate the
// `input_sha256` field so a second examiner can verify they have the same
// input bytes the original examiner used.

/// Compute the SHA-256 of a file on disk and return it as a lowercase hex
/// string. Session-gated (require_session) but takes no other validation —
/// the operator is trusted to point at a real file. Errors propagate as
/// AppError::Io if the file is missing or unreadable.
#[tauri::command(rename_all = "snake_case")]
pub async fn file_compute_sha256(
    token: String,
    path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let _session = require_session(&state, &token)?;

    let path_buf = std::path::PathBuf::from(&path);
    if !path_buf.exists() {
        return Err(AppError::Io(format!(
            "file does not exist: {path}"
        )));
    }
    if !path_buf.is_file() {
        return Err(AppError::Io(format!(
            "path is not a regular file: {path}"
        )));
    }

    uploads::re_hash_file(&path_buf).map_err(|e| AppError::Io(format!("hash failed: {e}")))
}

/// Delete a person's photo file from disk and clear the entity's photo_path
/// column. Idempotent — no error if the photo was already gone.
#[tauri::command(rename_all = "snake_case")]
pub async fn person_photo_delete(
    token: String,
    entity_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    let entity = entities::get_entity(&state.db.forensics, entity_id).await?;
    if entity.is_deleted != 0 {
        return Err(AppError::EntityNotFound { entity_id });
    }

    if let Some(photo_path) = entity.photo_path.as_deref() {
        uploads::delete_person_photo(photo_path)?;
    }

    sqlx::query("UPDATE entities SET photo_path = NULL, updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?")
        .bind(entity_id)
        .execute(&state.db.forensics)
        .await
        .map_err(AppError::from)?;

    info!(
        username = %session.username,
        entity_id = entity_id,
        "person photo deleted"
    );

    Ok(())
}

// ─── Business logo upload (migration 0005) ──────────────────────────────────

/// Upload a logo for a business entity. Validates that the entity exists and
/// is a business, copies the logo into the business-logo tree, and updates the
/// entity's `photo_path` column. Returns the updated photo_path so the
/// frontend can render it via `convertFileSrc()`.
#[tauri::command(rename_all = "snake_case")]
pub async fn business_logo_upload(
    token: String,
    entity_id: i64,
    source_path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let session = require_session(&state, &token)?;

    // Verify the entity exists and is a business
    let entity = entities::get_entity(&state.db.forensics, entity_id).await?;
    if entity.is_deleted != 0 {
        return Err(AppError::EntityNotFound { entity_id });
    }
    if entity.entity_type != "business" {
        return Err(AppError::EntityNotABusiness {
            entity_id,
            entity_type: entity.entity_type.clone(),
        });
    }

    // Copy the logo to the business-logo tree
    let appdata = appdata_root();
    let stored_path = uploads::upload_business_logo(&source_path, &entity.case_id, entity_id, &appdata)?;
    let stored_str = stored_path.to_string_lossy().into_owned();

    // Update the entity row with the new photo_path. We go through a direct
    // UPDATE because entity_update would also require re-validating all the
    // other fields — we only want to touch photo_path here.
    sqlx::query("UPDATE entities SET photo_path = ?, updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?")
        .bind(&stored_str)
        .bind(entity_id)
        .execute(&state.db.forensics)
        .await
        .map_err(AppError::from)?;

    info!(
        username = %session.username,
        entity_id = entity_id,
        "business logo uploaded"
    );

    Ok(stored_str)
}

/// Delete a business logo file from disk and clear the entity's photo_path
/// column. Idempotent — no error if the logo was already gone.
///
/// NOTE: intentionally does NOT validate entity_type == "business" — if
/// someone retypes an entity, they should still be able to clear the
/// orphaned logo path.
#[tauri::command(rename_all = "snake_case")]
pub async fn business_logo_delete(
    token: String,
    entity_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    let entity = entities::get_entity(&state.db.forensics, entity_id).await?;
    if entity.is_deleted != 0 {
        return Err(AppError::EntityNotFound { entity_id });
    }

    if let Some(logo_path) = entity.photo_path.as_deref() {
        uploads::delete_business_logo(logo_path)?;
    }

    sqlx::query("UPDATE entities SET photo_path = NULL, updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?")
        .bind(entity_id)
        .execute(&state.db.forensics)
        .await
        .map_err(AppError::from)?;

    info!(
        username = %session.username,
        entity_id = entity_id,
        "business logo deleted"
    );

    Ok(())
}
