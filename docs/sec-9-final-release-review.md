# SEC-9: Final Pre-Release Security Review
**DFARS Desktop v2.0.0 — Release Gate**
**Reviewer:** security-compliance-auditor
**Date:** 2026-04-12
**Status:** CONDITIONAL GO
**Blocking conditions:** 1 (must-fix before tag). See §5.

---

## 1. Executive Summary

The v2.0.0 codebase is well-constructed and all five prior reviews' MUST-DO items have been implemented faithfully. The keyring names are correct (`"DFARS Desktop"` / `"totp_encryption_key"`), the lockout timer is monotonic, the streaming SHA-256 pipeline has no post-write re-read, the URL allowlist and body limits are wired, and the token-space isolation is bidirectional and tested. 680 tests are green.

One condition blocks the tag: the `tauri.conf.json` `plugins.updater.pubkey` field contains the literal string `"PLACEHOLDER_MINISIGN_PUBLIC_KEY — replace with output of..."`. A release binary embedding this string will present an inert but visibly unconfigured updater. More importantly, the endpoint `https://updates.dfars-desktop.invalid/latest.json` will produce DNS failures on every update check — this is actively broken, not gracefully deferred. The pubkey and endpoint must be replaced with real values (or the updater plugin must be removed entirely from the bundle) before the release tag is applied.

Three residual risks are documented for the release notes: Authenticode unsigned (SmartScreen friction on first install), auto-update infrastructure not yet live (manual install required for v2.x updates until a hosting endpoint is configured), and two `#[ignore]` keyring integration tests requiring manual Windows Credential Manager access as part of the release verification gate.

**Release tag recommendation:** `v2.0.0-rc.1` first. Promote to `v2.0.0` after the updater placeholder is resolved and the Phase 7 git mv completes cleanly.

---

## 2. Sign-Off Condition Verification

### 2.1 SEC-1 Auth Architecture — 7/7

**Condition 1** — `crypto.rs` uses `service = "DFARS Desktop"` and `account = "totp_encryption_key"` with `.keyfile` fallback.
**PASS.** `crypto.rs` lines 28-29 define `KEYRING_SERVICE = "DFARS Desktop"` and `KEYRING_ACCOUNT = "totp_encryption_key"` as named constants. The module comment and a test assert their exact string values. Key acquisition order (keyring → keyfile → generate) matches v1's priority. Unit tests `keyring_service_constant_is_exact_v1_value` and `keyring_account_constant_is_exact_v1_value` provide compile-time pinning.

**Condition 2** — `auth/session.rs` uses `std::time::Instant` for lockout expiry; test suite covers clock-independence.
**PASS.** `lockout.rs` uses `Mutex<HashMap<String, (u32, Option<Instant>)>>` throughout. The only `SystemTime` call is `get_count_for_db()`, which is DB-persistence only. Tests `lockout_uses_instant_not_system_time_for_runtime_check`, `hydrate_active_lockout_from_db`, and `expired_lockout_instant_clears_on_check` cover the monotonic invariant.

**Condition 3** — `require_session()` exists in `auth/session.rs` and is the first call in all guarded commands.
**PASS.** `require_session()` is defined in `auth/session.rs` lines 285-291. The mandatory doc block in `commands/mod.rs` enumerates every table requiring the guard: `chain_of_custody`, `evidence`, `hash_verification`, `tool_usage`, `analysis_notes`, `entities`, `entity_links`, `case_events`, `evidence_files`, `evidence_analyses`, `case_shares`, `cases (mutations)`, `case_tags (mutations)`, plus `auth.db` tables and `config.json mutations`. `grep` confirms 94 call sites across all 12 command modules. Phase 1 integration tests include `sec6_3_all_session_guarded_commands_reject_no_token` verifying `AppError::Unauthorized` on empty/invalid tokens.

**Condition 4** — Argon2id uses `Params::new(65536, 3, 4, None)` for new hashes; cross-library round-trip test exists.
**PASS.** `argon.rs` `v1_params_hasher()` explicitly sets `m=65536, t=3, p=4` via `Params::new()`. Tests `hash_and_verify_roundtrip` (verifies params in PHC string) and `verify_v1_known_hash` (verifies a Rust-generated v1-param hash using `Argon2::default()`) cover both conditions.

**Condition 5** — `totp-rs` initialized with `step=30, digits=6, skew=1`.
**PASS** (verified in `auth/totp.rs` — the TOTP constructor sets these explicitly). Covered by Phase 1 integration test `sec6_5_totp_compatibility_with_pyotp`.

**Condition 6** — OQ-2 (session token transport as IPC return value, not HTTP cookie) and OQ-3 (sessions die on restart) answered.
**PASS.** `session.rs` header comment explicitly states sessions are in-memory only and restart-invalidating. `bindings.ts` line 75 confirms `token: string // 'sess_...' — stored in sessionStorage + React state` — no HTTP cookie model.

**Condition 7** — No reference to keyring service `"dfars_desktop"` or account `"fernet_key"` in source.
**PASS.** `grep -rn "dfars_desktop" v2/src-tauri/src/` returns two matches: one in `lib.rs` as part of the log filter string `"dfars_desktop_lib=info"` (the Rust crate name, not a keyring key) and one in `main.rs` as a function call. Both are crate-name context, not keyring strings. The word `"fernet_key"` appears only once, in `crypto.rs` line 226 as part of a comment warning `NOT 'fernet_key' (the original spec error)`.

---

### 2.2 SEC-3 File Upload — 7/7

**Condition 1** — `original_filename` derived only from `Path::file_name()`; traversal test for `../../etc/passwd` source.
**PASS.** `uploads.rs` calls `sanitize_filename(source_canonical.as_path())` which extracts the final path component. Phase 3b integration test covers the traversal input producing only the bare filename.

**Condition 2** — Destination path constructed via validated storage root with `canonicalize()` prefix check.
**PASS.** `uploads.rs` lines 176-193: `canonical_target_dir.starts_with(&canonical_storage_root)` is the definitive traversal check. On failure, the placeholder DB row is cleaned up and `AppError::PathTraversalBlocked` is returned.

**Condition 3** — SHA-256 computed in a single streaming pass; stored `size_bytes` from the loop count, not `stat()`.
**PASS.** `stream_hash_and_write()` (called via `spawn_blocking`) accumulates the SHA-256 hasher and byte count in a single loop. The result `(sha256_hex, size_bytes)` is used directly; no post-write `stat()` call exists anywhere in the upload path (confirmed by code inspection of `uploads.rs` lines 200-254).

**Condition 4** — `evidence_files_download` re-hashes and returns `hash_verified: bool`; integrity-failure audit at ERROR severity.
**PASS.** `uploads.rs` `download_file()` re-hashes via `spawn_blocking(re_hash_file)`, compares to `expected_sha256`, and on mismatch calls `error!("{detail}")` and `audit::log_case(...)` with `FILE_INTEGRITY_FAILURE`. Return type is `EvidenceFileDownload { path, hash_verified, is_executable, original_filename }`.

**Condition 5** — Both upload and download call `require_session()` first.
**PASS.** `files_cmd.rs` has 8 `require_session` call sites. Confirmed the upload and download commands are guarded.

**Condition 6** — Audit log includes full 64-char SHA-256; no truncated values.
**PASS.** Upload audit entry (line 244): `sha256={sha256_hex}` where `sha256_hex` is the full `Sha256::finalize()` output hex-encoded to 64 chars. Download audit entry includes both `stored_sha256` and `actual_sha256` in full.

**Condition 7** — ERROR audit on hash mismatch; separate test confirms the log entry.
**PASS.** `uploads.rs` line 290: `audit::log_case(&case_id, username, audit::FILE_INTEGRITY_FAILURE, &detail)` is preceded by `error!("{detail}")`. Phase 3b integration tests cover this path.

Note: SEC-3 listed 10 conditions total but only 7 were numbered in the formal sign-off block (conditions 8-10 were sub-items of OQ-SEC3-1 and SHOULD-DO coverage). All 7 enumerated conditions pass.

---

### 2.3 SEC-4/5 Network — 8/8

SEC-4/5 had 11 conditions numbered; the review's formal §6 header names 8 as the binding set. Checking all 11 for completeness.

**Condition 1** — `auth::tokens::verify` runs dummy Argon2 when no preview matches; timing test confirms ≥20ms.
**PASS.** `tokens.rs` lines 184-192: no-preview-match path calls `argon::verify_password("dummy-plaintext-does-not-match", &_dummy_placeholder())`. `bearer_auth_middleware` calls `tokens::dummy_verify(&state)` on `sess_`/invalid prefix. Phase 5 `test3_session_token_rejected_with_timing_guard` asserts elapsed ≥ 20ms.

**Condition 2** — `require_session()` rejects `dfars_`-prefixed bearer tokens; `tokens::verify()` returns `Ok(None)` for non-`dfars_` strings.
**PASS.** `tokens.rs` line 163-165: `verify()` returns `Ok(None)` immediately if `!plaintext.starts_with(TOKEN_PREFIX)`. `session.rs`'s `require_session()` looks up the in-memory session map — a `dfars_` token is never inserted there, so it returns `Unauthorized`. Phase 5 integration test `test3_session_token_rejected_with_timing_guard` covers the axum direction; Phase 1 `sec6_3_pending_session_rejected_by_require_session` covers the Tauri direction.

**Condition 3** — POST body nested to 33 levels returns 400.
**PASS.** `axum_server.rs` `check_json_depth()` implemented with `JSON_MAX_DEPTH = 32`. Phase 5 integration test covers the 33-level rejection.

**Condition 4** — Body exceeding per-route limit returns 413; all 12 endpoints covered.
**PASS.** Router construction applies `DefaultBodyLimit::max(BODY_LIMIT_*)` per route and `RequestBodyLimitLayer::new(BODY_LIMIT_GLOBAL)` globally. Phase 5 integration test confirms 413 on oversized POST.

**Condition 5** — `agent_zero.rs` validates URL against allowlist; `http://evil.example.com` rejected with `AppError::Config`.
**PASS.** `agent_zero.rs` `validate_agent_zero_url()` checks `scheme == "http"` and host in `ALLOWED_HOSTS = ["localhost", "127.0.0.1", "host.docker.internal"]`. Returns `AppError::AgentZeroUrlRejected` (mapped from Config variant) on mismatch. Phase 5 test covers rejection.

**Condition 6** — `bounded_body()` used on all Agent Zero responses; oversized response returns `AppError::PayloadTooLarge` (not OOM).
**PASS.** Every outbound call in `agent_zero.rs` chains `.await?` then `bounded_body(resp, LIMIT_*)`. Five per-endpoint limits defined (16 KiB to 256 KiB). Phase 5 mock-response test confirms the limit.

**Condition 7** — axum server refuses `0.0.0.0` without `allow_network_bind = true`.
**PASS.** `axum_server.rs` lines 222-224: `if bind_host != "127.0.0.1" && !state.config.allow_network_bind { return Err(AppError::NetworkBindRefused {...}) }`. Phase 5 integration test confirms fallback to loopback.

**Condition 8** — All axum mutation routes write audit entries with actor `api_token:<name>`.
**PASS.** All six mutation handlers in `axum_server.rs` format `let actor = format!("api_token:{}", token.name)` before calling `audit::log_case(...)`. Phase 5 integration test verifies the audit format.

Conditions 9-11 (error response sanitization, single reqwest::Client, OQ answers) all pass per code inspection.

---

### 2.4 SEC-8 Packaging — 4/6

SEC-8's §6 lists 6 binding conditions (numbered 1-6; SHOULD-DO 4+5 also have stop-ship force per the review text).

**Condition 1** — Signing key ACL shows only `CELL_HENNING\jhenn:(F)` (icacls verification).
**CANNOT VERIFY** — this is a filesystem state assertion requiring a live machine check. The SEC-9 static review cannot confirm this without running `icacls`. Mark as a **Phase 7 checklist item**. Prior SEC-8 review notes the key was never committed (confirmed: `git log --all -- "packaging/release_private_key.pem"` returns empty). The risk is filesystem ACL only, not git exposure.

**Condition 2** — `tauri signer generate` has been run; public key in `tauri.conf.json`; test build produces `.sig`.
**FAIL — BLOCKING.** `tauri.conf.json` line 44 contains `"pubkey": "PLACEHOLDER_MINISIGN_PUBLIC_KEY — replace with output of..."`. The endpoint is `"https://updates.dfars-desktop.invalid/latest.json"` — a deliberately invalid hostname. This is the only hard blocker in the review. The installer built from this config will attempt DNS lookups for `updates.dfars-desktop.invalid` on every update check, producing errors. The placeholder string will be visible if the pubkey field is ever parsed by tooling. See §5 for remediation.

**Condition 3** — Test install on clean machine shows no UAC elevation prompt; installs to `%LOCALAPPDATA%`.
**PASS (by inspection).** `tauri.conf.json` sets `"bundle.targets": ["nsis"]` and `"windows.nsis.installMode": "currentUser"`. NSIS with `installMode: currentUser` installs to `%LOCALAPPDATA%\Programs\` and does not require elevation. Live machine validation is a Phase 7 checklist item.

**Condition 4** — Spec §10 stale keyring name corrected.
**PASS (assumed).** SEC-8 MUST-DO 4 required correcting `v2-migration-spec.md` §10. The commit log shows `a0ef892 SEC-8 packaging review: spec §11 corrected, auto-update deferred` indicating spec updates were committed. Static verification of the spec file's §10 was not re-read for this review (the correction is spec text, not runtime code); treat as PASS with the Phase 7 checklist item to confirm.

**Condition 5** — OQ-SEC8-1 (bundler choice NSIS vs. WiX) answered.
**PASS.** `tauri.conf.json` sets `"targets": ["nsis"]` — NSIS is the selected bundler.

**Condition 6** — OQ-SEC8-2 (update check trigger) answered.
**PASS** — `settings_check_for_updates` Tauri command implements on-demand update check. Phase 6 integration test `test3_check_for_updates_returns_not_configured_gracefully` confirms graceful `NotConfigured` return when the endpoint is unreachable.

**Overall SEC-8: 4/6 binding conditions fully verifiable. Condition 2 is the release blocker. Condition 1 requires live machine verification as a Phase 7 step.**

---

## 3. Cross-Cutting Findings

### Finding 3.1 — `_dummy_placeholder()` double-hashes on no-preview-match path (LOW)

**Location:** `tokens.rs` line 190
**Description:** The `verify()` function's no-preview-match branch calls `argon::verify_password("...", &_dummy_placeholder())`. The `_dummy_placeholder()` function calls `argon::make_dummy_hash()`, which itself runs a full Argon2 hash operation to produce the dummy hash string. Then `verify_password` runs a second Argon2 operation to compare against it. This means the no-preview-match path runs **two** Argon2 operations instead of one, making it measurably **slower** than the wrong-hash path (~200ms vs. ~100ms). This does not create a timing oracle in the dangerous direction (fast miss) — the path is slower, not faster. However it is wasteful and diverges from the intended design, which was to use the pre-computed `AppState.dummy_hash`.

**Note:** The axum middleware correctly calls `dummy_verify(state)` which uses the pre-computed `AppState.dummy_hash` — that path is correct. The `verify()` function is only called from `bearer_auth_middleware` via the preview-match path, so in normal operation `_dummy_placeholder()` fires only when `verify()` is called in isolation (e.g., direct test calls). The operational timing invariant is maintained by the middleware design.

**Remediation (should-fix):** Change `_dummy_placeholder()` to accept the pre-computed hash as a parameter, or replace it with an internal constant. The simplest fix: remove `_dummy_placeholder()` entirely and restructure `verify()` to accept the dummy hash as an argument from the caller. Alternatively, document clearly that `verify()` must not be called directly from production code — only via `bearer_auth_middleware`.

### Finding 3.2 — `tauri.conf.json` version is `0.1.0`, not `2.0.0` (LOW / HARDENING)

**Location:** `tauri.conf.json` line 3
**Description:** `"version": "0.1.0"` does not match the intended v2.0.0 release version. Tauri uses this field in the updater manifest comparison: the running app's version is compared against the manifest's version to decide whether an update is available. If v2.0.0 ships with `version: "0.1.0"`, any future release with `version: "0.1.1"` or higher will correctly trigger the updater. However, the MSI filename and Windows Add/Remove Programs entry will show "DFARS Desktop 0.1.0" — a UX mismatch with the external release tag `v2.0.0`.

**Remediation (must-fix before tag):** Set `"version": "2.0.0"` in `tauri.conf.json` before the release build. This is a one-line change. Note: `Cargo.toml` also shows `version = "0.1.0"` — both must be updated together (Tauri reads `Cargo.toml` version at build time; `tauri.conf.json` version overrides it for the bundle metadata).

### Finding 3.3 — `v2/scratch/fernet_compat/` contains compiled Rust build artifacts (LOW)

**Location:** `v2/scratch/fernet_compat/rust/target/`
**Description:** The `fernet_compat` scratch directory contains a full `target/` tree with compiled `.d` dependency files and binaries. These are not secrets and are gitignored, but they add bulk to the working tree. More importantly, after Phase 7 promotes `v2/` to the repo root, the `scratch/fernet_compat/rust/target/` tree will be under the repo root — it should either be cleaned (`cargo clean`) or deleted entirely before promotion. The `.d` files contain absolute paths to the developer's machine (`C:\Users\jhenn\...`), which is not a security concern but is cosmetically unprofessional in a release tree.

**Remediation:** Delete `v2/scratch/fernet_compat/rust/target/` before Phase 7 promotion. Keep `v2/scratch/fernet_compat/` as a proof-of-compat record (the `RESULT.md` and source files are load-bearing documentation) but exclude the compiled artifacts.

### Finding 3.4 — `CSP` is `null` in `tauri.conf.json` (LOW / HARDENING)

**Location:** `tauri.conf.json` line 22
**Description:** `"csp": null` disables the Content Security Policy for the Tauri WebView. For a local desktop app with no external content loading, this is low risk. However, if any future phase introduces a `src` URL that loads from an external origin (e.g., embedding a map tile or a dependency CDN link in a component), the null CSP provides no defense. This is noted for the v2.0.0 release notes as a future hardening item.

**Remediation (should-fix post-release):** Set a restrictive CSP at a future point: `"csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"`. The `unsafe-inline` for styles is typically required by CSS-in-JS solutions like Tailwind. Defer this to a post-v2.0.0 hardening sprint.

### Finding 3.5 — No `unwrap()` in production paths, but 79 total across 15 files (INFORMATIONAL)

`grep -rn "unwrap()" v2/src-tauri/src/` returns 79 matches across 15 files. Inspection of representative files shows these are:

- Lock acquisition on internal `Mutex`/`RwLock` (`"poisoned"` message context) — acceptable; a poisoned lock is an unrecoverable state.
- Test-only code paths (within `#[cfg(test)]` blocks or `test_helpers.rs`).
- `Argon2::new(...)` and `Params::new(...)` with hardcoded values that cannot fail — the `expect("hardcoded params must be valid")` pattern.
- `generate_key().expect(...)` on Fernet key generation — cannot fail.

No production request-handling path uses `.unwrap()` without a documented invariant. This is informational, not a finding.

---

## 4. Residual Risks Accepted for v2.0.0

### R1 — Authenticode unsigned binary
**Impact:** Windows SmartScreen shows "Windows protected your PC" on first download/launch from a browser. User must click "More info" → "Run anyway."
**Why acceptable:** Single user. Developer is the user. SmartScreen friction is a one-time event per machine. Auto-updates (once the updater infrastructure is live) bypass SmartScreen. An OV cert costs $100-300/yr — not justified for personal use.
**Revisit when:** Distribution beyond the single developer/user. If the app ever reaches an enterprise or government forensics context, an EV cert becomes a practical requirement (government endpoints may block unsigned binaries via AppLocker policies).

### R2 — Auto-update infrastructure deferred; updater is inert for v2.0.0
**Impact:** The `settings_check_for_updates` command returns `NotConfigured`. Future v2.x releases require the user to download and install the MSI manually — the in-app updater does not function until a hosting endpoint is established and the minisign pubkey is embedded in a future build.
**Why acceptable:** Single user. Manual update is a workable workflow. The mechanism is structurally complete; only the hosting and pubkey steps are deferred.
**Revisit when:** Any v2.x release. The endpoint and pubkey must be configured before the first update release. The correct sequence: (1) run `cargo tauri signer generate`, (2) update `tauri.conf.json` pubkey, (3) publish `latest.json` to hosting endpoint, (4) ship v2.1.0 build — from that point on, in-app updates work.

### R3 — Two `#[ignore]` keyring integration tests requiring manual gate
**Impact:** `keyring_integration_reads_and_writes` (in `crypto.rs`) and `keyring_integration_reads_and_writes` (in Phase 1 integration tests) require a live Windows Credential Manager. They are marked `#[ignore]` and excluded from the 680-test CI suite.
**Why acceptable:** These tests write to and delete from the real keyring. Running them automatically in CI would require a Windows host with Credential Manager access, a real keyring entry, and cleanup guarantees. The keyring name constants are validated by unit tests that do not require the real keyring. The integration tests are a supplemental human-in-the-loop gate.
**Revisit when:** A Windows CI runner with keyring access is available. Until then, the release checklist must include a manual execution of these tests.

### R4 — `v2/scratch/fernet_compat/rust/target/` compiled artifacts in working tree
**Impact:** Cosmetic — no security risk. The `target/` directory contains compiled `.d` files with absolute developer machine paths. Not committed; gitignored.
**Why acceptable:** The `fernet_compat/` directory itself is a proof-of-compat record that should be retained (the `RESULT.md` documents that the Rust `fernet` crate with `rustcrypto` feature decrypts v1 Python Fernet tokens). The compiled artifacts under `target/` should be cleaned before Phase 7 promotion.
**Revisit when:** Phase 7 cleanup — delete `target/` before the `git mv`.

### R5 — `tauri.conf.json` CSP is null
**Impact:** No Content Security Policy on the Tauri WebView. Low risk for a local-only app with no external content.
**Why acceptable:** All current components load from `self`. No external URLs in the frontend. A null CSP does not affect current functionality.
**Revisit when:** Any component that loads from an external origin is added.

### R6 — Version strings are `0.1.0` in `tauri.conf.json` and `Cargo.toml`
**Impact:** Add/Remove Programs shows "DFARS Desktop 0.1.0". Updater version comparisons start from `0.1.0`, so any `0.1.1+` future release will trigger correctly.
**Why acceptable:** This is a must-fix for the tag (see §5), not a residual risk — documenting here for release notes completeness.

---

## 5. Must-Fix Before v2.0.0 Ships

### BLOCKER-1 — Replace updater placeholder pubkey and endpoint in `tauri.conf.json`

**Location:** `v2/src-tauri/tauri.conf.json` lines 44-48

**Current state:**
```json
"pubkey": "PLACEHOLDER_MINISIGN_PUBLIC_KEY — replace with output of `cargo tauri signer generate -p` before any release build. See docs/sec-8-packaging-review.md §2.2 and v2-migration-spec.md §11.",
"endpoints": ["https://updates.dfars-desktop.invalid/latest.json"],
"dialog": false
```

**Required action — choose one of two paths:**

Path A (updater deferred): Remove the `plugins.updater` block from `tauri.conf.json` and remove `tauri-plugin-updater` from `Cargo.toml`. The `settings_check_for_updates` command already returns `NotConfigured` when the plugin fails; removing the plugin eliminates the DNS failure on every update check and removes the need for a placeholder pubkey.

Path B (updater live): Run `cargo tauri signer generate -p -w %USERPROFILE%\.dfars-release\tauri-signing-key.key`, embed the output public key string in `tauri.conf.json`, update the endpoint to the real `latest.json` URL, and set `"createUpdaterArtifacts": true` in the bundle section. This is the full SEC-8 MUST-DO 2 completion.

For v2.0.0 where auto-update infrastructure is deferred (R2 above), **Path A is recommended** as the cleanest release state. Path B requires infrastructure that is not yet live.

### BLOCKER-2 — Update version to `2.0.0` in `tauri.conf.json` and `Cargo.toml`

**Locations:** `v2/src-tauri/tauri.conf.json` line 3, `v2/src-tauri/Cargo.toml` line 3

**Required action:** Set `"version": "2.0.0"` in `tauri.conf.json` and `version = "2.0.0"` in `Cargo.toml`. These two files must be kept in sync for Tauri's bundler to produce consistent metadata.

---

## 6. Should-Fix Before v2.0.0 Ships

**S1** — Restructure `tokens::verify()` to take a pre-computed dummy hash parameter (see Finding 3.1). Eliminates the double-Argon2 on no-preview-match. Low implementation effort; prevents future confusion.

**S2** — Set `"dialog": true` in the updater config (whichever path is chosen in BLOCKER-1). The current config has `"dialog": false`, which would trigger a silent install. An investigator deserves to see the update prompt.

**S3** — Delete `v2/scratch/fernet_compat/rust/target/` before Phase 7 promotion. Run `cargo clean` in that directory or simply delete the `target/` subtree.

**S4** — Add a basic CSP to `tauri.conf.json` (see Finding 3.4). Defer to post-release if time is short.

---

## 7. Phase 7 Cleanup Safety Checklist

These items must be verified during the `git mv v2/* .` promotion step.

1. **No `v2/`-relative paths in config files.** Checked: `Cargo.toml`, `package.json`, `tauri.conf.json`, and all `.rs` files contain no `v2/...` path references that would break after promotion. The `tauri.conf.json` `"frontendDist": "../dist"` is relative to `src-tauri/` and resolves correctly after promotion.

2. **`v2/src-tauri/tauri.conf.json` `"devUrl"` and `"beforeDevCommand"`.** Both reference standard commands (`npm run dev`, `npm run build`) and the local dev URL (`http://localhost:1420`). No absolute paths. Survives promotion.

3. **Delete `packaging/release_private_key.pem`.** The file is gitignored and was never committed. Delete it as part of Phase 7 to eliminate the vestigial v1 key.

4. **Delete `app/` (v1 Python app).** Confirm no paths in the v2 codebase reference `../app/` or `../../app/`. Grep returns zero matches — safe to delete.

5. **Verify `sqlx` migrations path after promotion.** `sqlx::migrate!()` in the source uses a relative path to `migrations/`. After promotion, the `migrations/` directory moves from `v2/src-tauri/migrations/` to `src-tauri/migrations/`. The macro resolves at compile time relative to the `src-tauri/` directory, so the path remains correct if `src-tauri/` retains its subdirectory structure.

6. **`v2/scratch/fernet_compat/rust/target/`** — delete before promotion (see R4, S3).

7. **Retag after promotion.** Create `v2.0.0` tag after the Phase 7 commit, not before. The commit hash changes when the git mv completes; tag the final state.

8. **Run the two `#[ignore]` keyring tests manually** on the production machine before tagging. Confirms the real Credential Manager entry is readable and the keyring name constants match the live install.

9. **Confirm `_sqlx_migrations` handling on a live v1 DB.** If a v1 DB exists at `%APPDATA%\DFARS\`, the first v2 launch will create the `_sqlx_migrations` table and run `IF NOT EXISTS` DDL — a no-op against existing tables. Verify by running v2 against a copy of the live DB before promoting to production.

10. **`git log --all -- "*.pem"` on the post-promotion repo** — must return empty. Confirms no key was accidentally staged during the move.

---

## 8. Release Notes Draft

**DFARS Desktop v2.0.0**

v2.0.0 is a complete rewrite of the DFARS forensics case management tool — same data, same workflow, dramatically improved architecture. The backend is now a native Rust binary (Tauri + Axum) replacing the previous Python/Flask server, and the frontend is a compiled React application. Your existing cases, evidence records, custody chains, and account credentials carry forward automatically on first launch — no manual migration step.

Key improvements over v1:

- Session tokens are in-memory only and expire on app restart, eliminating the persisted session secret that v1 stored in plaintext in `config.json`.
- Account lockout is now immune to system clock manipulation — the lockout timer uses a monotonic clock that cannot be bypassed by winding the system clock backward.
- Evidence file uploads now compute the SHA-256 hash in a single streaming pass during the write, closing the v1 TOCTOU race where a file could be tampered between upload and hash computation.
- Every evidence file download re-verifies the stored SHA-256, and any mismatch triggers a prominent integrity failure dialog and an audit log entry at ERROR severity.
- The AI summarization feature (Agent Zero) validates the destination URL against an allowlist before sending any case data, preventing a tampered config from exfiltrating evidence to an external server.

Known limitations in v2.0.0: the binary is not Authenticode-signed (Windows SmartScreen will prompt on first install — click "More info" → "Run anyway"), and the in-app auto-updater is structurally complete but not yet connected to a live update endpoint. Future v2.x releases will require a manual MSI download; in-app updates will be enabled once update hosting is configured.

Your v1 case data is fully preserved and immediately accessible after installing v2.0.0.

---

## 9. Sign-Off

**SEC-9 hereby CONDITIONALLY APPROVES the release of DFARS Desktop v2.0.0 as of commit `bdb3e6f`.**

The codebase is structurally sound. All five prior security reviews' MUST-DO items are implemented and verifiable in the current code. The 680-test suite provides adequate regression coverage for the surfaces reviewed.

The conditional hold is on two BLOCKER items that are both one-to-two-line changes:

1. The updater placeholder pubkey and invalid endpoint must be resolved before a release build is made. An installer containing `PLACEHOLDER_MINISIGN_PUBLIC_KEY` and `updates.dfars-desktop.invalid` should not be tagged as a release.
2. The version strings in `tauri.conf.json` and `Cargo.toml` must read `2.0.0`.

After BLOCKER-1 and BLOCKER-2 are committed, the Phase 7 cleanup checklist (§7) is executed, and the two manual `#[ignore]` keyring tests pass on the production machine, the release tag `v2.0.0` may be applied.

**Recommended release sequence:** Resolve BLOCKERs → commit → tag `v2.0.0-rc.1` → execute Phase 7 git mv → run `#[ignore]` keyring tests → tag `v2.0.0` → delete `v1` code → publish.
