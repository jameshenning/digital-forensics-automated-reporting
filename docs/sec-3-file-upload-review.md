# SEC-3: File Upload Security Architecture Review
**DFARS Desktop v2 — Pre-Implementation Security Gate**
**Reviewer:** security-compliance-auditor
**Date:** 2026-04-12
**Status:** APPROVED WITH CONDITIONS
**Phase 3b implementation:** BLOCKED pending resolution of MUST-DO items 1, 2, 3, and 4. All other Phase 3 work (evidence CRUD, custody, hashes, tools, analysis) may proceed in parallel.

---

## 1. Executive Summary

The v1 file upload implementation is defensible for a local desktop app: Werkzeug's `secure_filename()` prevents the most obvious filename attacks, and the path structure keeps files under a per-evidence subdirectory. The v1 metadata extractor (`file_metadata.py`) is admirably minimal — stdlib only, no third-party parsers — and deserves to be ported with the same discipline to v2.

Three concerns must be resolved before Phase 3b implementation begins. First, the `evidence_files_upload` command signature in the spec accepts a `file_path` parameter, meaning the frontend passes a filesystem path from the user's machine rather than a byte stream — this creates a path traversal vector if the resolved absolute path is not canonicalized and confirmed to lie within an allowed root before the file is read. Second, the spec describes no SHA-256 pipeline at all; v2 must compute the hash in a single streaming pass concurrent with the write, so the stored hash covers exactly the bytes on disk — not the bytes at source. Third, the storage layout comment in `0001_init.sql` (`stored_path` comment says "absolute path under `%APPDATA%\DFARS\evidence_files\`") conflicts with v1's actual behavior, which stores files under `<evidence_drive_path>/DFARS_Evidence/<case_id>/<evidence_id>/` when a drive is configured. The v2 spec must resolve this ambiguity before implementation.

The OneDrive sync risk (see §2.10) is a finding unique to the specific user's machine configuration. It is not a code defect, but it is a forensic integrity concern that the UI should surface explicitly on first upload.

---

## 2. Findings by Area

### 2.1 Storage Layout

**v1 behavior:** `paths.py`'s `evidence_files_dir()` returns one of two roots depending on whether a case has an `evidence_drive_path` set:
- With drive: `<drive>/DFARS_Evidence/<case_id>/<evidence_id>/`
- Without drive (fallback): `%APPDATA%\DFARS\evidence_files\<case_id>/<evidence_id>/`

Both paths sanitize `case_id` and `evidence_id` through `_safe_path_segment()`, which allows only `[a-zA-Z0-9._-]` and strips leading/trailing `.` and `_`. The actual filename stored on disk is `<8-hex-uuid-prefix>_<safe_filename>` — a UUID prefix ensures uniqueness; the safe name makes the file recognizable in a file manager.

**v2 concern:** The `0001_init.sql` comment says `stored_path` is "absolute path under `%APPDATA%\DFARS\evidence_files\`" — this implies a flat layout. This conflicts with v1's per-evidence subdirectory structure and, more importantly, with v1's external drive support. The spec §6 command signature `evidence_files_upload(evidence_id, file_path)` does not mention a drive path or a target directory root, leaving the storage location entirely to the implementer.

**Recommendation — structured layout:**

Use a structured layout mirroring v1:
- With a case-level `evidence_drive_path`: `<drive>/DFARS_Evidence/<case_id>/<evidence_id>/`
- Without (fallback): `%APPDATA%\DFARS\evidence_files\<case_id>/<evidence_id>/`

Tradeoffs:
- Flat layout (`evidence_files/<sha256>.bin`): eliminates traversal risk and collision risk, but a file manager browse exposes only opaque hashes, losing the `case_id`/`evidence_id` organizational context and making manual recovery harder.
- Structured layout by case/evidence: marginally leaks case/evidence IDs to anyone with filesystem access, but they are already in the DB alongside the path. Cleanup on evidence delete is straightforward (delete the subdirectory). Better for an investigator who needs to locate files manually.

**Decision:** Use the structured layout for v1 compatibility and operational clarity. Store the on-disk name as `<file_id>_<sanitized_original_filename>` where `file_id` is the DB autoincrement ID assigned at insert — this ensures uniqueness without an extra UUID call, and the `file_id` prefix makes it trivially traceable back to the DB row. Do not use only `<sha256>.bin` as the on-disk name: SHA-256 collisions across different cases would silently share files, and two uploads of the same file to different evidence items should be stored as independent copies for chain-of-custody independence.

The `stored_path` column comment in `0001_init.sql` must be updated to reflect the actual path structure. No schema DDL change is needed.

---

### 2.2 Filename Collision and Path Traversal

**v1 behavior:** Werkzeug's `secure_filename(f.filename)` strips path separators, null bytes, and most special characters. A fallback UUID name is generated if the result is empty. The final on-disk name is `<8-hex>_<safe_name>`.

**v2 concern:** The `evidence_files_upload` Tauri command accepts a `file_path` — a path to the source file on the user's filesystem (e.g., a file they picked via a Tauri file dialog). Unlike Flask's `request.files`, this is not a byte stream — it is a path that Rust will open and read. If the command opens the path without canonicalization, a carefully crafted `file_path` containing `..` sequences could cause the app to read from (or write to) an unintended location.

The target stored filename is a separate concern: the `original_filename` stored in the DB is the last component of the user-provided path, and if that is written directly as the stored file's name, path separators in the filename string (`\`, `/`) will traverse directories on disk.

**Canonical pattern for v2:**

1. Call `std::fs::canonicalize()` on the source `file_path` before opening it. If the call fails (path does not exist, symlink loop), reject the upload.
2. Derive the `original_filename` as only the final path component (the `Path::file_name()` result in Rust), never the full path or any parent components.
3. Reject the upload if `original_filename` contains any of: `\`, `/`, `:`, `\0` (null byte), or any Unicode control character in the range U+0000–U+001F, or is empty after stripping whitespace.
4. Further sanitize `original_filename` by replacing any character that is not `[a-zA-Z0-9._\- ]` with `_`. (Note: spaces are allowed for readability but the stored-on-disk name should have spaces replaced with `_`.)
5. Reject if the UTF-8-encoded sanitized `original_filename` exceeds 200 bytes (conservative, within Windows 260-char `MAX_PATH` with the prefix and directory path).
6. The on-disk stored name must be `<file_id>_<sanitized_name>` or a UUID-prefixed equivalent — never the raw `original_filename`.
7. After constructing the full target path, call `canonicalize()` on its parent directory and verify the canonical path begins with the expected storage root. This is the definitive traversal check: even if the constructed path looks clean, a symlink in the directory hierarchy could redirect it outside the root.

**Do not** rely solely on character filtering for traversal prevention — the canonical-path prefix check (step 7) is the only defense that is robust against symlink-based attacks.

---

### 2.3 SHA-256 Pipeline and TOCTOU

**v1 behavior:** v1 calls `f.save(stored_path)` first, then calls `sha256_of(stored_path)` — the hash is computed by re-reading the file that was written. Between `save()` and `sha256_of()`, another process could modify the stored file, causing the recorded hash to differ from the original source. This is a TOCTOU (time-of-check to time-of-use) race. v1 also checks `stat().st_size` after save, which has the same race.

**Impact for chain-of-custody:** If the stored hash is computed from the post-write file and that file is tampered with between write and hash, the DB records a hash that does not match the original evidence. The hash appears valid because it was computed from the already-tampered bytes. This is the chain-of-custody integrity failure mode.

**v2 requirement — single-pass streaming hash+write:**

The implementation must compute SHA-256 concurrent with writing the file to disk in a single streaming pass. This pattern in Rust:

1. Open the source file for reading.
2. Open the destination file for writing (create new, fail if exists).
3. Initialize a `sha2::Sha256` hasher.
4. In a loop: read a chunk from source, update the hasher with the chunk bytes, write the chunk to destination.
5. After the loop (before closing the destination), call `hasher.finalize()` to get the digest.
6. Record this digest as `sha256`. Record `size_bytes` from the byte-count accumulated during the loop — not from a subsequent `stat()`.

This approach guarantees: (a) the hash covers exactly the bytes written; (b) `size_bytes` matches the hash; (c) there is no re-read after write. The destination file should be opened with the Rust equivalent of O_CREAT | O_EXCL to prevent overwriting an existing file.

**Crate guidance:** Use the `sha2` crate (already in the RustCrypto ecosystem, consistent with the argon2/fernet choices). The `sha2::Sha256` hasher implements `std::io::Write`, which enables a clean copy-with-update loop without unsafe code.

---

### 2.4 MIME Type Detection

**v1 behavior:** `file_metadata.guess_mime(filename)` calls `mimetypes.guess_type(filename)` — this trusts the filename extension. There is no byte-sniffing. The `mime_type` column in the DB records the extension-derived value.

**Risk:** A file named `malicious.pdf` that is actually a PE executable will be recorded as `application/pdf`. For a forensics tool this is a chain-of-custody concern: the MIME type in the record should reflect what the file actually is, not what the filename claims.

**v2 recommendation:**

Store two values per upload:
- `mime_type` (DB column, existing): the sniffed MIME type, derived from the first 16–512 bytes of the file content.
- `claimed_mime_type` (additional note in `metadata_json`): the extension-derived MIME type.

Use the `infer` crate (Rust) for byte-sniffing. It covers the most common forensic file types (PE, ZIP, PDF, Office, images, audio/video) and returns a typed result without needing a full parse. Fall back to `"application/octet-stream"` if the first bytes match no known signature.

**Security decisions must use the sniffed type, not the extension-derived type.** This affects: which metadata extractor branch runs (§2.6), and what warning the UI displays if the user tries to open the file (§2.8).

**Schema note:** No DDL change is needed — the existing `mime_type` column stores the sniffed type, and `metadata_json` can carry `claimed_mime: "application/pdf"` as a supplemental field.

---

### 2.5 File Size Limits

**v1 behavior:** No explicit file size limit. Flask's default `MAX_CONTENT_LENGTH` is not set. For a typical evidence file (screenshot, PDF, log export) this is fine. For a forensics workstation that might upload raw disk images, unlimited upload risks disk exhaustion.

**Forensics context:** Legitimate evidence files range from a few KB (a log snippet) to hundreds of GB (a full disk image). A hard block at any single threshold may frustrate investigators working with large artifacts. The goal is not to prevent large uploads but to prevent accidental disk exhaustion from an upload loop bug.

**v2 recommendation — two-tier limit:**

- **Soft limit: 2 GB.** Files larger than 2 GB are accepted but the UI displays a persistent warning: "Large file uploaded (X GB). Verify sufficient disk space before continuing." Log at WARN level.
- **Hard limit: 50 GB.** Reject uploads larger than 50 GB with `AppError::FileTooLarge`. Rationale: a 50 GB ceiling allows full disk images of mobile devices and most laptop drive images while preventing obviously pathological inputs. This limit should be configurable in `config.json` under a `max_upload_bytes` key (defaulting to 53,687,091,200 bytes = 50 GiB) so an investigator with a multi-TB NAS can raise it.

**Implementation note:** Check the file size via `std::fs::metadata().len()` before opening the file for the streaming copy. This is a cheap pre-check that avoids starting a long streaming operation only to fail at 50 GB. The pre-check is not a security boundary (the file could grow after the check), but the streaming write can also track bytes written and abort if the limit is exceeded mid-stream.

---

### 2.6 Metadata Extraction DoS

**v1 behavior:** `file_metadata.py` is stdlib-only. The only potentially slow operations are:
- `_text_metadata()`: reads up to 256 KB of a text file in memory. Bounded.
- `_pdf_metadata()`: reads only the first 1024 bytes. Bounded.
- `_image_metadata()`: reads 64 bytes. Trivially bounded.
- `sha256_of()`: streams the full file in 1 MB chunks. For a 10 GB file this takes ~30 seconds.

There are no third-party parsers. The `try/except: return` pattern wraps every extraction path. This is already the correct approach and avoids all library-crash DoS vectors.

**v2 concern:** The spec plans `file_metadata.rs` as an in-process Tauri command. The SHA-256 streaming operation for large files will run for seconds-to-minutes. Tauri commands run on the async tokio executor; a long-running blocking operation on the async executor starves other commands and makes the UI unresponsive.

**v2 recommendation:**

Option (c) — "skip extraction entirely in Phase 3b and add it in a later phase" — is the safest. However, given that v1's extractor is already stdlib-only and crash-resistant, the better recommendation is option (b) with a scoped timeout:

**SHOULD implement in Phase 3b:**
- Run the SHA-256 streaming write (§2.3) in a `tokio::task::spawn_blocking()` closure. This moves the blocking I/O off the async executor without requiring a separate process. The Tauri command awaits the blocking task's `JoinHandle`.
- Run the lightweight metadata extraction (image header, PDF version string, text sample) inside the same `spawn_blocking()` closure immediately after the write completes. This is cheap (<1 ms for stdlib-only operations on any file up to 50 GB) and does not need a separate timeout.
- Wrap the metadata extraction in a `catch_unwind()` (Rust) equivalent: use a closure that returns `Option<serde_json::Value>` and returns `None` on any panic or error. Store `metadata_json = null` in the DB if extraction fails. Never surface a metadata extraction failure as a command error that blocks the upload.

**What NOT to do in v2:**
- Do not spawn a child process for extraction (too much overhead for stdlib-only work).
- Do not call any third-party parser crates (PyPDF2 equivalent, Exiftool FFI) in Phase 3b. If richer metadata is needed later, scope it as a separate SEC review.

---

### 2.7 Evidence Delete Cleanup

**v1 behavior:** `soft_delete_evidence_file()` sets `is_deleted = 1` but does not unlink the file on disk. The `delete_evidence_file` route confirms the `evidence_id` matches before soft-deleting (preventing one user from soft-deleting another user's files — irrelevant in single-user but good hygiene). The disk file is never touched.

**Policy options analysis:**

- **(a) Refuse evidence_delete when evidence_files rows exist:** Consistent with Phase 3a's `EvidenceHasDependents` pattern for other dependent tables. Forces an explicit per-file delete first. High auditability. Frustrating for investigators who want to clean up a test evidence item.
- **(b) Cascade soft-delete to evidence_files when evidence is soft-deleted:** But `evidence` does not have a soft-delete — `evidence_delete` is a hard delete (FK RESTRICT means it currently refuses). If evidence is deleted, its file records would be orphaned.
- **(c) Hard cascade that unlinks disk files:** Maximum cleanup. Least auditable — the disk bytes are gone and the DB record is gone. For a forensics tool this is the most dangerous option: if an investigator deletes an evidence item by mistake, the raw files are gone.

**Recommendation:**

Use option **(a) for now**: `evidence_delete` should already refuse when `evidence_files` rows with `is_deleted = 0` exist (the FK RESTRICT on `evidence_files.evidence_id` enforces this at the DB level). Soft-deleting all file rows before deleting the evidence item is the correct workflow. The disk files remain after soft-delete — they are never automatically unlinked in Phase 3b.

Add a separate `evidence_files_purge(file_id)` command (Phase 3b or later) that hard-deletes a soft-deleted file record AND unlinks the disk file, but only after the investigator has explicitly confirmed intent. This command must emit an audit log entry with the SHA-256 of the file that was purged, providing a permanent record that the file existed and was deliberately removed.

**Do not silently unlink disk files on soft-delete.** The disk file is the primary artifact; the DB record is the index. For chain-of-custody defensibility, the disk file should persist until an explicit purge action is taken.

---

### 2.8 Download Path and Executable File Risk

**v1 behavior:** `evidence_files_download` in the v1 REST API returns the file bytes directly over HTTP. The browser/client decides what to do with them. There is no shell-open or OS "open with default app" behavior in v1.

**v2 concern:** `evidence_files_download(file_id) -> PathBuf` returns the path to the stored file. The React frontend presumably calls `tauri::api::shell::open()` or passes the path to a Tauri dialog. On a Windows forensics workstation, this means double-clicking a PE executable recovered from a suspect device would execute it.

**The forensics context matters:** Investigators routinely handle executable artifacts. Blocking `.exe` opens would be operationally unacceptable. However, the risk of accidental execution is real: a tired investigator clicking "Open" on a suspicious binary they intended to inspect in a hex editor could compromise the workstation and potentially the chain of custody for other evidence.

**v2 recommendation:**

1. `evidence_files_download` must re-hash the stored file before returning the path (§2.9 below) and report the hash status in the return value.
2. The returned type should be `EvidenceFileDownload { path: PathBuf, hash_verified: bool, sniffed_mime: String, is_executable: bool }`.
3. Set `is_executable = true` if the sniffed MIME type is `"application/x-msdownload"`, `"application/x-executable"`, `"application/x-dosexec"`, or `"application/x-elf"`, or if the first two bytes are `MZ` (PE magic bytes, `0x4D 0x5A`).
4. The React frontend must display a warning dialog if `is_executable = true`: "This file is a Windows executable. Opening it will run it on this machine. Are you sure?" The user must click a distinct confirmation button (not just "OK") to proceed.
5. Do not attempt to quarantine or block the file — this is a forensics tool where executables are expected. The warning is informational, not a gate.
6. Do not use `tauri::api::shell::open()` as the sole "open" mechanism without this check. The frontend should pass the path to the OS shell opener only after the executable check dialog is confirmed.

---

### 2.9 TOCTOU on SHA-256 Verification During Download

**v1 behavior:** No integrity re-verification on download. The stored hash is recorded at upload time and never re-checked. If someone with local filesystem access modifies the stored file between upload and download, the tampered bytes are served without warning.

**Chain-of-custody impact:** This is the primary integrity vector in the threat model. A local attacker who can write to `%APPDATA%\DFARS\evidence_files\` can substitute any file without detection — the DB still shows the original hash and the original filename. The investigator sees consistent metadata but corrupted evidence.

**v2 requirement:** `evidence_files_download` must re-hash the stored file on every call and compare to the DB record. This is not optional.

**Design:**
1. On download request, read the stored `sha256` from the DB.
2. Stream-hash the disk file (same `sha2::Sha256` streaming approach as §2.3, in `spawn_blocking()`).
3. Compare. If they match: return `{ ..., hash_verified: true }`.
4. If they do not match: return `{ ..., hash_verified: false }` AND emit an audit log entry at ERROR severity: `"INTEGRITY FAILURE: file_id={} evidence_id={} stored_sha256={} actual_sha256={}"`. Do not refuse to return the path (the investigator may still need the file to investigate the tampering), but make the failure unmistakable.
5. The React frontend must display a prominent integrity status on every download: a green "Hash verified" badge if `hash_verified = true`, and a red "INTEGRITY FAILURE — file may have been tampered with" banner if false. The banner must not be dismissable without the investigator explicitly acknowledging it.

**Performance note:** For a 10 GB file this adds 15–30 seconds to the download operation on a modern drive. This is acceptable for a forensics tool — hash verification is a documented part of digital evidence procedure. If the user's evidence files are all small (< 100 MB) the latency is negligible. Do not add a "skip verification" option in Phase 3b.

---

### 2.10 Storage Directory Permissions and OneDrive Sync Risk

**ACL recommendation:** On first use, `evidence_files_root()` should be created with ACLs restricted to the current user (SDDL: `D:P(A;;FA;;;SY)(A;;FA;;;CO)(A;;FA;;;BA)(A;;FA;;;BU)` or equivalent Tauri/Rust Windows API call). This prevents another local Windows user account from browsing evidence files. On a shared-use workstation (lab computer), this is meaningful even though the app is single-user. The Tauri installer does not set directory ACLs — the app must set them at first launch.

**OneDrive sync risk — THIS IS A DIRECT CONCERN FOR THIS USER:**

James's `%APPDATA%` path is OneDrive-synced per the project memory. This means `%APPDATA%\DFARS\evidence_files\` (the fallback storage root) will silently sync all uploaded evidence files to Microsoft's cloud unless the directory is excluded from OneDrive sync.

**Impact:**
- Evidence files containing PII, PHI, or law-enforcement-sensitive data are exfiltrated to a third-party cloud service without the investigator's explicit consent.
- Chain-of-custody defensibility is compromised: an opposing party could argue that evidence uploaded to OneDrive was accessible to Microsoft and potentially tampered with.
- Privacy regulations (if any case involves EU data subjects, GDPR Article 46 cross-border transfer provisions apply since Microsoft's datacenters outside the EU may process the data).

**v2 requirement:** On first launch, or on first file upload attempt, the app must:
1. Check whether `%APPDATA%\DFARS\evidence_files\` (or its parent) is covered by an OneDrive sync configuration. This can be detected by checking for a `desktop.ini` with `[LocalizedFileNames]` or the presence of the OneDrive shell extension attributes, or by checking the path against the registry key `HKCU\Software\Microsoft\OneDrive\Accounts\Personal\ScopeIdToMountPointPathCache`. A simpler detection: check if `%APPDATA%` resolves to a path under the user's OneDrive folder.
2. If OneDrive sync is detected, display a blocking warning (cannot be dismissed with "OK" alone): "Your evidence files storage directory is inside OneDrive. Evidence files will be synchronized to Microsoft's cloud. This may compromise chain-of-custody integrity and violate privacy obligations for sensitive case data. Options: (a) Configure an external evidence drive for this case. (b) Exclude `%APPDATA%\DFARS\evidence_files\` from OneDrive sync. Do not upload until one of these steps is taken."
3. Record this warning in the audit log regardless of the user's response.

**Alternate path:** Encourage investigators to always configure a case-level `evidence_drive_path` pointing to an external USB drive or a local non-synced directory. The UI should visually surface "No evidence drive configured" as a yellow warning state on any case.

---

### 2.11 Audit Logging

**v1 behavior:** `audit.log_case()` is called on upload (`FILE_UPLOADED`) and soft-delete (`FILE_DELETED`). The upload log includes: `case_id`, `evidence_id`, file count, and drive path. The delete log includes: `evidence_id`, `original_filename` (quoted), and the first 16 chars of the SHA-256 with `...` appended.

**For chain-of-custody defensibility, v2 audit entries for evidence file operations must capture:**

For `evidence_files_upload`:
- `file_id` (DB autoincrement ID)
- `evidence_id`
- `case_id`
- `original_filename`
- `stored_path` (absolute)
- `sha256` (full 64-character hex digest — not truncated)
- `size_bytes`
- `sniffed_mime_type`
- `uploaded_by` (username from session)
- `uploaded_at` (UTC timestamp from the app, not DB default)
- `source_path` (the original file path the user selected — not stored in the DB but important for the audit trail)

For `evidence_files_download`:
- `file_id`, `evidence_id`, `case_id`
- `hash_verified` (true/false)
- `stored_sha256` (from DB), `actual_sha256` (computed at download time)
- `opened_by`, `opened_at`

For `evidence_files_soft_delete`:
- `file_id`, `evidence_id`, `case_id`
- `original_filename`, `full sha256` (not truncated)
- `deleted_by`, `deleted_at`

For `evidence_files_purge` (future command):
- All of the above plus a mandatory `justification` field.

**The v1 truncation of SHA-256 to 16 chars (`ef.sha256[:16]...`) must not be ported to v2.** Truncated hashes are not suitable for chain-of-custody records. The full 64-character hex digest must appear in every audit log entry touching a file.

---

### 2.12 Session Guard Coverage

**v2 design:** `require_session()` is implemented in `auth/session.rs` and is confirmed present. The spec and SEC-1 MUST-DO 3 already require it as the first call in every evidence mutation command. The `evidence_files` table is listed in the mandatory guard list in `session.rs` line 276.

**Verdict for file upload commands:** `evidence_files_upload`, `evidence_files_download`, and a future `evidence_files_purge` must all call `require_session()` as their first statement. This is consistent with the existing requirement and requires no new design decisions.

**No elevated session is recommended.** The single-user local-only threat model does not justify a separate elevated session tier for file operations. The existing 30-minute inactivity timeout in `require_session()` is appropriate.

---

## 3. Required Changes Before Implementation (MUST-DOs)

These are hard gates. Phase 3b file upload code MUST NOT be written until the spec issues are resolved, and each MUST-DO must be verifiably implemented before the Phase 3b PR is approved.

**MUST-DO 1 — Resolve storage layout ambiguity in the spec and implement v1-compatible directory structure.**

The `0001_init.sql` comment for `stored_path` says "absolute path under `%APPDATA%\DFARS\evidence_files\`" — this is the *fallback* root only. Update the comment to: "absolute path under `<evidence_drive_path>/DFARS_Evidence/<case_id>/<evidence_id>/` (or `%APPDATA%\DFARS\evidence_files\<case_id>/<evidence_id>/` if no drive configured)."

The `evidence_files_upload(evidence_id, file_path)` command signature in v2-migration-spec.md §6 must be updated to `evidence_files_upload(evidence_id, file_path, case_id)` — the case_id is required to determine the storage root (it provides the `evidence_drive_path`). Alternatively, derive the case_id by querying the DB via `evidence_id`. Either approach must be documented in the spec before implementation.

**MUST-DO 2 — Implement safe filename handling with the canonical-path traversal check.**

The Rust implementation of `evidence_files_upload` must:
- Derive `original_filename` as only the final path component (`Path::file_name()`), never the full source path.
- Reject uploads where the Unicode-normalized `original_filename` contains any of: `\`, `/`, `:`, `\0` (null byte), or any code point in U+0000–U+001F.
- Reject if the UTF-8-encoded sanitized `original_filename` exceeds 200 bytes.
- Sanitize the display name: replace any character not in `[a-zA-Z0-9._\- ]` with `_`.
- Name the on-disk file `<file_id>_<sanitized_name>` (where `file_id` is assigned by a DB insert of a partial record, or a pre-allocated UUID).
- After constructing the full target path, call `canonicalize()` on the target directory and verify its canonical form starts with the expected storage root. Reject the upload if this check fails.

**MUST-DO 3 — Implement single-pass streaming SHA-256 hash+write.**

The upload implementation must compute SHA-256 in the same streaming pass as the file write (using `sha2::Sha256` from the RustCrypto ecosystem). The `sha256` and `size_bytes` recorded in the DB must come from this single pass — not from a subsequent `stat()` or re-read of the disk file. The entire streaming operation must run in `tokio::task::spawn_blocking()`.

**MUST-DO 4 — Implement hash re-verification on download.**

`evidence_files_download` must re-hash the stored file on every call and compare to the DB-stored SHA-256. The return type must include a `hash_verified: bool` field. If `hash_verified = false`, an audit log entry at ERROR severity must be written. The React frontend must display an unmistakable integrity status indicator on every download.

**MUST-DO 5 — Emit the OneDrive sync warning on first upload.**

Before the first file is written to `%APPDATA%\DFARS\evidence_files\`, detect whether that directory path is under OneDrive sync coverage. If it is, display a blocking UI warning (not dismissable with a single "OK") and write an audit log entry regardless of the investigator's response. See §2.10 for the exact warning text and detection approach.

---

## 4. Recommended Improvements (SHOULD-DOs)

These are worth implementing in Phase 3b if scope allows, but do not block the upload gate.

**SHOULD-DO 1 — Use the `infer` crate for byte-sniffing and store sniffed MIME as `mime_type`.**
Store the extension-derived MIME as `claimed_mime` in `metadata_json`. Use sniffed MIME for all security-relevant decisions (executor warning, metadata extractor branch selection). See §2.4.

**SHOULD-DO 2 — Surface a per-file executable warning in the download flow.**
`evidence_files_download` return type should include `is_executable: bool` (detected by MZ header or sniffed MIME). The React frontend must display a confirmation dialog before invoking the OS shell opener. See §2.8.

**SHOULD-DO 3 — Run upload I/O in `tokio::task::spawn_blocking()`.**
All blocking file I/O (the streaming hash+write, the metadata extraction) must run in a `spawn_blocking()` closure to prevent starving the async executor. See §2.6.

**SHOULD-DO 4 — Implement `evidence_files_purge(file_id, justification)` with hard-delete + audit.**
Add a purge command that hard-deletes a soft-deleted file record and unlinks the disk file, requiring a mandatory `justification` string. The audit entry must include the full SHA-256 of the purged file. See §2.7.

**SHOULD-DO 5 — Set ACLs on the evidence files directory at first launch.**
On first launch (or first upload), restrict `%APPDATA%\DFARS\evidence_files\` to the current user only. Use the Windows API via Rust or a Tauri plugin. See §2.10.

**SHOULD-DO 6 — Enforce a configurable file size hard limit.**
Reject uploads larger than 50 GiB (configurable via `max_upload_bytes` in `config.json`). Warn (but allow) uploads larger than 2 GiB. Check size before opening the source file and again mid-stream. See §2.5.

**SHOULD-DO 7 — Record `source_path` in the audit log for each upload.**
The path the investigator selected as the source file (`file_path` parameter) should appear in the upload audit log entry even though it is not stored in the DB. This provides provenance — an auditor can see that the file was taken from `D:\ForensicImages\SuspectLaptop\Documents\evil.xlsx` at upload time.

---

## 5. Open Questions

**OQ-SEC3-1 — External drive support in v2.**
The spec's `evidence_files_upload(evidence_id, file_path)` signature does not mention `evidence_drive_path` or case-level drive configuration. Does v2 plan to support the external drive model from v1 (files on a USB drive, not in `%APPDATA%`)? If yes, the command must accept or derive the target root. If no (v2 always stores in `%APPDATA%\DFARS\evidence_files\`), the `evidence_drive_path` column on `cases` becomes unused in v2 and the `0001_init.sql` comment is misleading. This must be decided before Phase 3b implementation.

**OQ-SEC3-2 — Multiple files per command invocation.**
v1's upload route accepts a `files` multipart list (multiple files per POST). The v2 spec shows `evidence_files_upload(evidence_id, file_path)` — singular. Does v2 upload one file per command call (Tauri IPC model) or should it accept a `Vec<PathBuf>`? One file per call is simpler to implement and audit (each call produces one audit log entry for one file). A `Vec<PathBuf>` variant would be a convenience wrapper. Recommend: one file per call. The frontend can batch multiple calls with a progress indicator.

**OQ-SEC3-3 — Metadata extraction scope for Phase 3b.**
Is the lightweight stdlib-equivalent metadata extraction (image dimensions from header bytes, PDF version from first 1024 bytes, text line/char count for files < 256 KB) in scope for Phase 3b, or is `metadata_json = null` acceptable for the initial implementation? The SEC-3 MUST-DOs do not require extraction — only that extraction does not block the upload. Confirm scope with the user.

**OQ-SEC3-4 — OneDrive detection mechanism.**
The recommended OneDrive detection approach (registry key check and/or `%APPDATA%` path resolution) requires Windows API access. Confirm with the implementation agent that the Tauri + Rust Windows API access is available for this check, or identify an alternative detection approach (e.g., checking for the `%OneDrive%` environment variable and comparing paths).

---

## 6. Sign-Off Conditions for SEC-3 Final Approval

The following must be true in the Phase 3b implementation PR before SEC-3 is closed:

1. The `evidence_files_upload` command derives `original_filename` from only the final path component. A test confirms that a source path containing `../../etc/passwd` produces `original_filename = "passwd"` with no traversal.

2. The uploaded file's destination path is constructed by joining the validated storage root with a sanitized, non-traversal filename. A `canonicalize()` check on the target directory confirms it falls within the expected root. A test confirms that a malicious UUID+filename combination that resolves to a path outside the storage root is rejected.

3. SHA-256 is computed in a single streaming pass during the write. A test confirms that the stored hash equals `sha256sum` of the on-disk file, and that the stored `size_bytes` equals the file size.

4. `evidence_files_download` re-hashes the stored file and returns `hash_verified: bool`. A test confirms that modifying the stored file on disk causes `hash_verified = false` on the next download call.

5. Both `evidence_files_upload` and `evidence_files_download` call `require_session()` as their first statement. A negative test confirms `AppError::Unauthorized` is returned without a valid session token.

6. Audit log entries for upload include: `file_id`, `evidence_id`, `case_id`, `original_filename`, `stored_path`, full 64-hex-char `sha256`, `size_bytes`, `uploaded_by`. No truncated SHA-256 values appear in any audit entry.

7. A test for the download integrity check confirms that an audit log entry at ERROR severity is written when `hash_verified = false`.

8. OQ-SEC3-1 (external drive support scope) is answered and the spec is updated to reflect the decision before implementation begins.

9. If the metadata extractor is included in Phase 3b, all extraction code runs inside `spawn_blocking()` and is wrapped in error handling that returns `metadata_json = null` on any failure. No metadata extraction failure causes the upload command to return an error.

10. The PR does not contain any call to `sha256()` or `stat()` on the stored file after the write completes — the hash and size must come from the streaming write pass.

---

## Appendix A: v1 Behaviors That Are PASS and Should Be Ported Unchanged

- **`_safe_path_segment()` sanitization for case_id and evidence_id in the storage path:** allowlist `[a-zA-Z0-9._-]`, strip leading/trailing `.` and `_`. Port this logic to Rust for the directory path construction.
- **UUID prefix on stored filenames:** prevents collision when the same source filename is uploaded multiple times to the same evidence item. Port the equivalent (use `file_id` prefix rather than UUID, for traceability).
- **Soft-delete model (`is_deleted = 1`):** correct for a forensics tool. Hard-delete is reserved for the explicit `purge` action.
- **`try/except: continue` pattern around per-file operations in a batch upload:** individual file failures must not abort the entire batch. Port to Rust as per-iteration `Result` handling that logs the failure and continues.
- **Audit log on upload and soft-delete:** confirmed presence of `FILE_UPLOADED` and `FILE_DELETED` audit events. v2 must emit equivalent events with the enhanced fields listed in §2.11.

---

## Appendix B: v2-migration-spec.md §6 Items Requiring Revision

1. `evidence_files_upload(evidence_id, file_path) -> EvidenceFile` — must add or derive `case_id` to resolve storage root (OQ-SEC3-1). Recommend adding `case_id` as an explicit parameter.
2. `evidence_files_download(file_id) -> PathBuf` — the return type must be richer than `PathBuf`. Recommend `-> EvidenceFileDownload` struct containing at minimum `{ path: PathBuf, hash_verified: bool, is_executable: bool }`.
3. A `evidence_files_purge(file_id, justification) -> ()` command should be added to the command surface. This is the controlled hard-delete path.

---

## Appendix C: Spec Comment to Update in 0001_init.sql

Line 204 currently reads:
```sql
stored_path TEXT NOT NULL,            -- absolute path under %APPDATA%\DFARS\evidence_files\
```

Update to:
```sql
stored_path TEXT NOT NULL,            -- absolute path: <drive>/DFARS_Evidence/<case_id>/<evidence_id>/<file_id>_<name>
                                      -- or %APPDATA%\DFARS\evidence_files\<case_id>/<evidence_id>/<file_id>_<name> (no drive configured)
```

This is a comment-only change — no DDL migration needed.
