/// Windows drive enumeration and bounded directory scan.
///
/// `list_drives()` uses `sysinfo::Disks` to enumerate available volumes.
/// `scan_drive()` walks a directory tree up to `max_depth = 10` and
/// `max_files = 100_000`, returning aggregate stats and the top-20 extensions.
///
/// Both functions are safe to call from async contexts — `scan_drive` is
/// wrapped in `tokio::task::spawn_blocking` because `walkdir` is sync I/O.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sysinfo::Disks;
use tracing::warn;

use crate::error::AppError;

// ─── Public data types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    /// e.g. "C:" or "E:".
    pub letter: String,
    /// Volume label reported by the OS (may be empty).
    pub label: Option<String>,
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// "fixed" | "removable" | "cdrom" | "network" | "unknown"
    pub drive_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveScanResult {
    pub root: PathBuf,
    pub file_count: u64,
    pub total_bytes: u64,
    /// Top 20 extensions by file count, e.g. [(".pdf", 321), (".docx", 88)].
    pub top_extensions: Vec<(String, u64)>,
}

// ─── Drive enumeration ────────────────────────────────────────────────────────

/// List all mounted drives visible to the OS.
pub async fn list_drives() -> Result<Vec<Drive>, AppError> {
    // sysinfo::Disks is sync — wrap in spawn_blocking for correctness.
    tokio::task::spawn_blocking(|| {
        let disks = Disks::new_with_refreshed_list();
        let mut result = Vec::new();

        for disk in disks.list() {
            let mount = disk.mount_point();
            // On Windows, mount_point is e.g. "C:\\" — extract drive letter.
            let letter = mount
                .to_str()
                .and_then(|s| {
                    let s = s.trim_end_matches(|c| c == '/' || c == '\\');
                    if s.len() >= 2 && s.chars().nth(1) == Some(':') {
                        Some(s[..2].to_uppercase())
                    } else {
                        Some(s.to_owned())
                    }
                })
                .unwrap_or_else(|| mount.to_string_lossy().into_owned());

            let label_raw = disk.name().to_string_lossy().into_owned();
            let label = if label_raw.is_empty() {
                None
            } else {
                Some(label_raw)
            };

            let drive_type = classify_disk_kind(disk.kind());

            result.push(Drive {
                letter,
                label,
                total_bytes: disk.total_space(),
                free_bytes: disk.available_space(),
                drive_type,
            });
        }

        Ok(result)
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking panicked: {e}")))?
}

fn classify_disk_kind(kind: sysinfo::DiskKind) -> String {
    match kind {
        sysinfo::DiskKind::HDD | sysinfo::DiskKind::SSD => "fixed".to_owned(),
        sysinfo::DiskKind::Unknown(_) => "unknown".to_owned(),
    }
}

// ─── Directory scan ───────────────────────────────────────────────────────────

const DEFAULT_MAX_DEPTH: usize = 10;
const DEFAULT_MAX_FILES: usize = 100_000;

/// Scan a directory tree and return aggregate statistics.
///
/// Hard-coded safety bounds: depth ≤ `max_depth`, files ≤ `max_files`.
/// Exceeding `max_files` returns `AppError::DriveScanTooLarge`.
///
/// Runs in `tokio::task::spawn_blocking` — do not call from a blocking context.
pub async fn scan_drive(
    path: &Path,
    max_depth: usize,
    max_files: usize,
) -> Result<DriveScanResult, AppError> {
    let path = path.to_path_buf();
    let max_depth = max_depth.min(DEFAULT_MAX_DEPTH);
    let max_files = max_files.min(DEFAULT_MAX_FILES);

    tokio::task::spawn_blocking(move || scan_sync(&path, max_depth, max_files))
        .await
        .map_err(|e| AppError::Internal(format!("scan_drive spawn_blocking panicked: {e}")))?
}

fn scan_sync(
    root: &Path,
    max_depth: usize,
    max_files: usize,
) -> Result<DriveScanResult, AppError> {
    use walkdir::WalkDir;

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut ext_counts: HashMap<String, u64> = HashMap::new();

    let walker = WalkDir::new(root)
        .max_depth(max_depth)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| {
            e.map_err(|err| warn!("scan_drive: skipping entry: {err}"))
                .ok()
        });

    for entry in walker {
        if !entry.file_type().is_file() {
            continue;
        }

        file_count += 1;
        if file_count > max_files as u64 {
            return Err(AppError::DriveScanTooLarge {
                file_count,
                limit: max_files as u64,
            });
        }

        if let Ok(meta) = entry.metadata() {
            total_bytes += meta.len();
        }

        let ext = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e.to_lowercase()))
            .unwrap_or_else(|| "(none)".to_owned());

        *ext_counts.entry(ext).or_insert(0) += 1;
    }

    // Sort by count descending, take top 20.
    let mut top_extensions: Vec<(String, u64)> = ext_counts.into_iter().collect();
    top_extensions.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top_extensions.truncate(20);

    Ok(DriveScanResult {
        root: root.to_path_buf(),
        file_count,
        total_bytes,
        top_extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn scan_counts_files() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        std::fs::write(dir.path().join("b.pdf"), "world").unwrap();

        let result = scan_drive(dir.path(), 5, 1000).await.unwrap();
        assert_eq!(result.file_count, 2);
        // top extensions should include .txt and .pdf
        let exts: Vec<&str> = result.top_extensions.iter().map(|(e, _)| e.as_str()).collect();
        assert!(exts.contains(&".txt") || exts.contains(&".pdf"));
    }

    #[tokio::test]
    async fn scan_too_large_errors() {
        let dir = tempdir().unwrap();
        // Create 5 files but set max_files = 3
        for i in 0..5 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), "x").unwrap();
        }
        let err = scan_drive(dir.path(), 5, 3).await.unwrap_err();
        assert!(matches!(err, AppError::DriveScanTooLarge { .. }));
    }
}
