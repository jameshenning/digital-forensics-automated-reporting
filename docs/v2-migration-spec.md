# DFARS Desktop v2 — Migration Spec

> Ground-up rebuild of DFARS Desktop on Tauri 2 + Rust + sqlx + React 19.
> v1 is frozen at tag `v1-final` (commit `11d435d`) and stays runnable during the entire rebuild.

## 1. Goals

- **Smaller, faster, signable binary.** Drop the ~57 MB Python bundle for a ~10–15 MB Tauri app. Native code + WebView means colder-start under 300 ms and a single signable `.exe`.
- **Type-safe IPC.** Rust `#[tauri::command]` + `tauri-specta` → generated TypeScript types. No more `fetch('/api/...')` string-soup across the Flask boundary.
- **Compile-time SQL.** sqlx `query!`/`query_as!` macros verified against a checked-in `.sqlx/` offline schema. Kills whole classes of "SELECT foo" typo bugs.
- **Feature parity with v1-final**, then cleanup. Nothing the user relies on today gets left behind; polish happens after parity lands.
- **Auditable upgrade path.** v1 `forensics.db` and `auth.db` must open in v2 unchanged (or through a one-shot, reversible migration). No data loss for existing installs.

## 2. Non-goals

- Cross-platform (macOS/Linux). Windows-only remains the target. Tauri keeps the door open but we don't spend cycles on it.
- Multi-user. Single-user enforcement is preserved end-to-end.
- Rewriting the forensic data model. Schema is v1-compatible; only the *access layer* changes.
- Replacing Agent Zero integration. Same HTTP contract, just a Rust `reqwest` client instead of a Python `requests` client.

## 3. Stack decisions

| Concern | Choice | Why |
|---|---|---|
| Shell | **Tauri 2 (stable)** | Native WebView2, code signing support, built-in updater, tiny footprint. |
| Backend lang | **Rust 1.80+** | Owned by Tauri; lets us share crypto/db code with the frontend via commands. |
| Async runtime | **tokio** (full) | Default Tauri runtime; needed for sqlx, reqwest. |
| Database | **sqlx 0.8** with `sqlite` + `runtime-tokio-rustls` + `macros` | Compile-time query checking; same SQLite file as v1. |
| Migrations | **sqlx-cli** embedded via `sqlx::migrate!` | Migrations live in `src-tauri/migrations/`. |
| Password hash | **argon2 0.5** (RustCrypto) | Default Argon2id params match v1 encoded strings → existing hashes verify unchanged. |
| TOTP | **totp-rs** | Matches v1's pyotp behavior (SHA-1, 6-digit, 30s); same Base32 secrets. |
| Symmetric crypto | **fernet 0.2** (or a hand-rolled AES-GCM if fernet rusts aren't maintained) | v1 uses Python `cryptography.fernet`; binary-compatible on the Rust side. Decision: verify fernet crate before locking in. |
| Keyring | **keyring 2.x** | Hits Windows Credential Manager just like Python `keyring`. |
| HTTP client | **reqwest 0.12** (rustls) | For Agent Zero calls. |
| Frontend build | **Vite 7** + **React 19** + **TypeScript 5.8** | Tauri 2 template default (2026-04). React 19 gives us Actions, the `use` hook, and improved Suspense for data loading. |
| UI components | **Shadcn/UI (Radix + Tailwind)** | Vendorable, offline-safe, replaces Bootstrap 5. Accessible by default. |
| Routing | **TanStack Router** | File-based, type-safe, first-class nested routing. |
| Server state | **TanStack Query** | Caches Tauri command responses with the same ergonomics as HTTP. |
| Graph viz | **Cytoscape.js** (replacing vis-network) | Actively maintained; better perf on 500+ node graphs. Vendored locally. |
| Timeline viz | **vis-timeline** (kept) | Still the best OSS timeline widget; vendored, no CDN. |
| Forms | **react-hook-form + zod** | zod schemas mirror Rust types (can codegen via `tauri-specta` later). |
| IPC codegen | **tauri-specta + specta** | Generates `bindings.ts` from `#[tauri::command]` signatures at build time. |
| Error model | **thiserror** (Rust) + a shared `AppError` enum exposed over IPC | Each command returns `Result<T, AppError>`; frontend discriminates on `code`. |
| Logging | **tracing** + **tracing-appender** (rolling file) | Writes to `%LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log`, matching v1. |
| Tests | **cargo test** for Rust, **Vitest** for React, **WebDriverIO + tauri-driver** for E2E | Full pyramid; v1 had only integration smoke tests. |
| Packaging | **tauri bundler** (Inno Setup under the hood) | One command for installer + updater bundle; replaces the custom PyInstaller/Inno split. |
| Updates | **tauri-plugin-updater** with Ed25519 signing | Matches v1's signing scheme; keys from `packaging/keygen.py` can be reused. |

### Decisions deliberately deferred

- **State management for transient UI state** (e.g. in-progress form drafts). TanStack Query + React component state should cover 95%; defer Zustand/Jotai until a real need shows up.
- **i18n.** Not in scope for v2.0; structure strings in a `t()` wrapper so retrofitting is mechanical.

## 4. Repository layout

```
dfars-desktop/                 # repo root (unchanged)
├── app/                       # v1 Python code (kept, still runnable from v1-final tag)
├── packaging/                 # v1 PyInstaller/Inno scripts (kept)
├── docs/
│   └── v2-migration-spec.md   # ← this file
├── v2/                        # NEW — everything v2 lives under here until parity
│   ├── src-tauri/
│   │   ├── Cargo.toml
│   │   ├── tauri.conf.json
│   │   ├── build.rs           # tauri-specta codegen hook
│   │   ├── migrations/        # sqlx migrations (0001_init.sql etc.)
│   │   ├── src/
│   │   │   ├── main.rs        # Tauri builder + command registry
│   │   │   ├── state.rs       # AppState (db pool, config, keyring handle)
│   │   │   ├── error.rs       # AppError + IPC serialization
│   │   │   ├── db/            # sqlx query modules, one file per table group
│   │   │   │   ├── mod.rs
│   │   │   │   ├── cases.rs
│   │   │   │   ├── evidence.rs
│   │   │   │   ├── custody.rs
│   │   │   │   ├── entities.rs
│   │   │   │   ├── links.rs
│   │   │   │   ├── events.rs
│   │   │   │   └── shares.rs
│   │   │   ├── auth/          # argon2, TOTP, session mgmt
│   │   │   │   ├── mod.rs
│   │   │   │   ├── argon.rs
│   │   │   │   ├── totp.rs
│   │   │   │   ├── session.rs
│   │   │   │   └── tokens.rs  # api token bearer auth
│   │   │   ├── crypto.rs      # Fernet wrapper, keyring integration
│   │   │   ├── agent_zero.rs  # reqwest client for plugin calls
│   │   │   ├── reports/       # markdown generator (mirrors v1 report_generator.py)
│   │   │   ├── drives.rs      # Windows drive enumeration + scan
│   │   │   ├── file_metadata.rs
│   │   │   ├── updater.rs     # hooks tauri-plugin-updater
│   │   │   └── commands/      # #[tauri::command] surface, grouped by domain
│   │   │       ├── mod.rs
│   │   │       ├── auth_cmd.rs
│   │   │       ├── cases_cmd.rs
│   │   │       ├── evidence_cmd.rs
│   │   │       ├── link_analysis_cmd.rs
│   │   │       ├── ai_cmd.rs
│   │   │       └── system_cmd.rs
│   │   └── tests/             # cargo test: integration tests against an ephemeral sqlite
│   ├── src/                   # React frontend
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── routes/            # TanStack Router tree
│   │   │   ├── __root.tsx
│   │   │   ├── auth.login.tsx
│   │   │   ├── auth.setup.tsx
│   │   │   ├── auth.mfa.tsx
│   │   │   ├── dashboard.tsx
│   │   │   ├── case.new.tsx
│   │   │   ├── case.$id.tsx
│   │   │   ├── case.$id.edit.tsx
│   │   │   ├── case.$id.link-analysis.tsx
│   │   │   └── case.$id.report.tsx
│   │   ├── components/        # Shadcn primitives + domain components
│   │   ├── lib/
│   │   │   ├── bindings.ts    # GENERATED by tauri-specta — do not edit
│   │   │   ├── query.ts       # TanStack Query client + keys
│   │   │   ├── auth.ts        # session hooks
│   │   │   └── utils.ts
│   │   └── styles/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   └── README.md              # v2-specific dev notes
└── README.md                  # top-level — updated at parity milestone
```

**Why a `v2/` subdirectory instead of a branch:** keeps both codebases runnable side-by-side on `main`, makes the diff easy to review, and avoids a big-bang merge. When v2 hits parity, `app/` and `packaging/` get deleted in a single commit and `v2/*` gets promoted to the root.

## 5. Data model — v1 → v2

The schema stays **byte-identical** to `app/schema/database_schema.sql` and `app/schema/auth_schema.sql`. v2 initializes an empty DB from a single sqlx migration that's a verbatim copy of v1's DDL; existing v1 installs open unchanged.

### Tables (from v1-final)

`forensics.db`:
- `cases` (PK `case_id TEXT`)
- `evidence` (PK `evidence_id TEXT`)
- `hash_verification`
- `chain_of_custody`
- `tool_usage`
- `analysis_notes`
- `case_tags`
- `report_templates`
- `entities` — soft-delete, investigator-curated
- `entity_links` — generic source→target, typed
- `case_events` — investigator timeline entries
- `evidence_files` — uploaded artifacts, sha256
- `evidence_analyses` — AI-generated forensic reports
- `case_shares` — email/print audit trail (added 2026-04-12)

`auth.db`:
- `users` (single-user enforced at app layer)
- `recovery_codes`
- `api_tokens`

### sqlx query style

One module per table group under `src-tauri/src/db/`. Example:

```rust
// src-tauri/src/db/cases.rs
pub async fn get_case(pool: &SqlitePool, id: &str) -> Result<Case, AppError> {
    sqlx::query_as!(
        Case,
        r#"SELECT case_id, case_name, description, investigator, ...
           FROM cases WHERE case_id = ?"#,
        id
    )
    .fetch_one(pool)
    .await
    .map_err(AppError::from)
}
```

The checked-in `.sqlx/` offline schema cache makes CI builds work without a live DB.

### Type model

Rust structs in `src-tauri/src/db/types.rs` derive `Serialize`, `Deserialize`, `specta::Type`, and (for queries) `sqlx::FromRow`. `tauri-specta` emits their TypeScript equivalents into `src/lib/bindings.ts` at build time. One source of truth.

## 6. Command surface (Tauri IPC)

v1 exposes two HTTP layers — internal session-gated routes (`/case/...`, `/api/internal/...`) and an external bearer-token REST API (`/api/v1/...`). v2 collapses the *internal* layer into Tauri commands, keeps the *external* layer as a Rust `axum` server mounted on a local port (still bearer-token-gated, same contract as v1, so Agent Zero pushes keep working unchanged).

### Auth commands
- `auth_setup_first_run(username, password) -> SessionInfo`
- `auth_login(username, password) -> LoginResult` (MFA-aware; returns `NeedsMfa | Ok(SessionInfo) | LockedOut`)
- `auth_verify_mfa(code) -> SessionInfo`
- `auth_logout()`
- `auth_change_password(old, new)`
- `auth_current_user() -> Option<SessionInfo>`
- `auth_mfa_enroll_start() -> MfaEnrollment` (returns provisioning URI + recovery codes)
- `auth_mfa_enroll_confirm(code)`
- `auth_mfa_disable(password)`
- `auth_tokens_list() -> Vec<ApiTokenListItem>`
- `auth_tokens_create(name) -> NewToken` (plaintext shown once)
- `auth_tokens_revoke(id)`

### Case commands
- `cases_list() -> Vec<CaseSummary>`
- `case_get(case_id) -> CaseDetail`
- `case_create(input) -> CaseDetail`
- `case_update(case_id, patch)`
- `case_delete(case_id)` (respects FK RESTRICT — frontend warns on dependent rows)
- `case_report_generate(case_id, format) -> PathBuf`
- `case_report_preview(case_id) -> String` (markdown)

### Evidence commands
- `evidence_add(case_id, input) -> Evidence`
- `evidence_delete(case_id, evidence_id)`
- `evidence_files_upload(evidence_id, source_path) -> EvidenceFile` — derives `case_id` and the case's `evidence_drive_path` via a DB lookup on `evidence_id`. Storage layout is `<evidence_drive_path or %APPDATA%\DFARS\evidence_files>\<case_id>\<evidence_id>\<file_id>_<sanitized_name>`. Files on an external forensic drive are the forensic-best-practice path; `%APPDATA%` is the fallback when the case has no drive configured. One file per command invocation — batching happens client-side. See SEC-3 MUST-DO 1/2/3 and OQ-SEC3-1 resolution.
- `evidence_files_download(file_id) -> EvidenceFileDownload { path: PathBuf, hash_verified: bool, is_executable: bool }` — re-hashes the stored file on every call and compares to the DB-stored SHA-256. `hash_verified = false` triggers an ERROR-severity audit entry and the frontend must surface an unmistakable integrity warning. `is_executable` detected by byte-sniffing via the `infer` crate (MZ header / ELF / Mach-O / script shebang). See SEC-3 MUST-DO 4 and SHOULD-DO 2.
- `evidence_files_purge(file_id, justification) -> ()` — controlled hard-delete path. Soft-deletes become normal via a separate soft-delete flow; purge is the audited, justified, permanent erasure. Unlinks the disk file and zero-fills the DB row after writing the full SHA-256 to the audit log for post-hoc chain-of-custody. See SEC-3 SHOULD-DO 4.
- `evidence_analyze(evidence_id, narrative) -> EvidenceAnalysis` (local, no AI)
- `evidence_forensic_analyze(evidence_id, narrative) -> EvidenceAnalysis` (AI via Agent Zero)

### Chain-of-custody / hashes / tools / analysis
- `custody_add`, `custody_update`, `custody_delete`
- `hash_add`
- `tool_add`
- `analysis_add`

### Link analysis
- `entities_list(case_id) -> Vec<Entity>`
- `entity_add(case_id, input) -> Entity`
- `entity_delete(case_id, entity_id)`
- `links_list(case_id) -> Vec<Link>`
- `link_add(case_id, input) -> Link`
- `link_delete(case_id, link_id)`
- `events_list(case_id) -> Vec<CaseEvent>`
- `event_add(case_id, input) -> CaseEvent`
- `event_delete(case_id, event_id)`
- `case_graph(case_id, filter) -> GraphPayload`
- `case_crime_line(case_id, start, end) -> TimelinePayload`

### AI helpers (Agent Zero)
- `ai_enhance(text) -> String`
- `ai_classify(text) -> ClassificationResult`
- `ai_summarize_case(case_id) -> CaseSummary`

### System
- `drives_list() -> Vec<Drive>`
- `drive_scan(case_id, path) -> ScanResult`
- `share_record(case_id, record_type, record_id, action, recipient, narrative)`
- `updater_check() -> UpdateInfo`
- `updater_install(update_id)`
- `settings_get_agent_zero() -> AgentZeroConfig`
- `settings_set_agent_zero(input)`
- `settings_get_smtp() -> SmtpConfig`
- `settings_set_smtp(input)`
- `settings_test_smtp()`
- `settings_test_agent_zero()`
- `audit_tail(limit) -> Vec<AuditEntry>`

### External REST API (bearer token, `axum`)

> **Revised 2026-04-13** — Q2 "minimal vs full port" resolved by data. Agent Zero plugin uses all 12 v1 endpoints (audited in `agent-zero/usr/plugins/_dfars_integration/helpers/dfars_client.py` + `api/dfars_forensic_analyze.py`). Port all 12.

12-endpoint surface, contract-compatible with v1's `/api/v1/*`:

| # | Method | Path | Notes |
|---|---|---|---|
| 1 | GET | `/api/v1/whoami` | returns the API token owner's name |
| 2 | GET | `/api/v1/cases` | list |
| 3 | POST | `/api/v1/cases` | create |
| 4 | GET | `/api/v1/cases/<id>` | detail |
| 5 | PATCH | `/api/v1/cases/<id>` | update |
| 6 | POST | `/api/v1/cases/<id>/evidence` | add evidence |
| 7 | POST | `/api/v1/cases/<id>/custody` | add custody event |
| 8 | POST | `/api/v1/cases/<id>/hashes` | add hash verification |
| 9 | POST | `/api/v1/cases/<id>/tools` | log tool usage |
| 10 | POST | `/api/v1/cases/<id>/analysis` | add analysis note |
| 11 | GET | `/api/v1/cases/<id>/report` | generate markdown report |
| 12 | GET | `/api/v1/cases/<id>/evidence/<eid>/files/<fid>/download` | stream stored file |

The server runs in-process on a tokio task using the same sqlx pool as the Tauri commands. Per-route body limits, JSON depth limit, and shared error shape come from SEC-4/5 — see below.

**Bearer token middleware (SEC-5 MUST-DO 1 — timing-oracle mitigation):**

Every request hits a middleware that verifies the `Authorization: Bearer dfars_...` header against `api_tokens`. The fast path looks up by `token_preview` (first 12 chars) to O(1), then runs a single Argon2 verify. **When no row matches the preview, middleware still runs a dummy Argon2 call against `AppState.dummy_hash`** so the no-match and wrong-hash code paths take ~equal time (~100 ms). No timing oracle.

**Token-space isolation (SEC-5 MUST-DO 2):**

Session tokens (`sess_...` from `require_session`) and API tokens (`dfars_...` from the axum middleware) are strictly disjoint. A session token passed to axum returns `Unauthorized`. An API token passed to a Tauri command returns `Unauthorized`. Both `auth/session.rs` and `auth/tokens.rs` carry a doc comment enforcing this invariant. QA writes negative tests confirming both directions.

**Per-route request body limits (SEC-5 MUST-DO 4):**

Global floor of 64 KiB via `RequestBodyLimitLayer::new(64 * 1024)`. Per-route override via `DefaultBodyLimit::max()`:

| Route | Limit |
|---|---|
| `POST /cases/<id>/tools` | 64 KiB (`command_used` can be long) |
| `POST /cases/<id>/analysis` | 32 KiB (long `description` field) |
| `POST /cases`, `PATCH /cases/<id>`, `POST /cases/<id>/evidence` | 16 KiB |
| `POST /cases/<id>/custody`, `POST /cases/<id>/hashes` | 8 KiB |

Over-limit returns HTTP 413 with `{"error": "Request body too large", "code": "PAYLOAD_TOO_LARGE"}`.

**JSON depth limit (SEC-5 MUST-DO 3):**

Custom `check_json_depth(bytes, max_depth=32)` runs before `serde_json::from_slice` in the body extractor. Deeply nested input (`{"a":{"a":...}}`) returns HTTP 400. Prevents stack overflow via untrusted JSON.

**Error response shape (SEC-5 MUST-DO — §2.13):**

All axum errors serialize as `{"error": "<human message>", "code": "<AppError variant name>", "details": {}}`. The `details` field is a whitelist — sqlite error strings, file paths, user hashes, and internal state MUST NEVER appear there. Reuses the existing `AppError` variants from Phase 1+ so Agent Zero's error parsing doesn't need a second dictionary.

**Bind-host gate (SEC-5 MUST-DO 5 — double opt-in for 0.0.0.0):**

`bind_host` defaults to `127.0.0.1` in `config.json`. To bind non-loopback (`0.0.0.0` for the Agent Zero Docker container), two config keys are required:

1. `bind_host = "0.0.0.0"` (the literal value)
2. `allow_network_bind = true` (explicit opt-in)

Without the second key, the axum startup code refuses to bind and surfaces `AppError::NetworkBindRefused`. When both are set, the settings UI displays a persistent amber warning banner, an audit entry is written at WARN on every startup, and the UI exposes `allow_network_bind` as an explicit checkbox with a scary label.

**Port (SEC-4/5 OQ-SEC5-1 resolved):**

`axum_port` in `config.json`, default `5099` (matches v1 and the Agent Zero plugin's default). Exposed via `settings_get_agent_zero` / `settings_set_agent_zero` so the user can change it without editing config.json directly.

**Audit log actor format (SEC-5 MUST-DO 8):**

axum mutation routes write audit entries with actor `api_token:<token_name>` (e.g. `api_token:Agent Zero`). Tauri session-authed commands write `user:<username>` (e.g. `user:james`). Distinct prefixes let audit queries filter by authentication source.

## 7. Auth / MFA parity

> **Revised 2026-04-13** after SEC-1 architecture review (see `docs/sec-1-auth-architecture-review.md`). The original spec had a critical keyring name bug that would have silently orphaned all v1 encrypted secrets on first v2 launch — now fixed below.

### Passwords (Argon2id)

- v1 hashes are `$argon2id$v=19$m=...` encoded strings produced by Python `argon2-cffi` with the library default `m=65536, t=3, p=4`. Rust's `argon2` 0.5+ `PasswordHash::new` + `Argon2::default().verify_password` reads them directly; no rehashing on login.
- **MUST (SEC-1 SHOULD-DO 1):** new hashes in v2 (initial user creation, password change, recovery code hashing) use an explicit `Params::new(65536, 3, 4, None)` — NOT `Argon2::default()`, because the Rust crate's default is weaker than `argon2-cffi`'s and using it would silently downgrade new credentials.
- Retain v1's defenses verbatim: constant-time username-enumeration guard with a pre-hashed `_DUMMY_HASH`, 1024-char password-length cap, username character allowlist `[a-zA-Z0-9._-]`.

### TOTP (MFA)

- v1 secrets are Base32, 6-digit, 30 s, SHA-1 (pyotp defaults). Rust `totp-rs` with `Algorithm::SHA1`, `digits=6`, `step=30`, `skew=1` matches byte-for-byte. Test with RFC 6238 vectors.
- During enrollment, the pending TOTP secret is held in the in-memory session state (as part of a `Pending` session variant), NOT re-fetched from the DB at confirm time — this prevents a secret-substitution attack.

### Recovery codes

- 10 codes generated at MFA enrollment. Each is Argon2id-hashed (using the explicit params above) and stored in `recovery_codes` with `used_at` NULL. On redemption, `used_at` is set; row is never reused.
- Codes are revoked and regenerated on MFA disable/re-enroll.
- **MUST (SEC-1 SHOULD-DO 2):** per-session rate limit on MFA verify — after 5 consecutive TOTP+recovery-code failures, the pending session is cleared and the user must restart from the password step. Logged to the audit trail.

### Account lockout (MUST-DO 2 — monotonic timer)

**Do not** replicate v1's `datetime.now()` wall-clock lockout — winding the system clock backward would bypass it.

- `AuthState` in `AppState` holds `failed_attempts: Mutex<HashMap<String, (u32, Option<Instant>)>>` keyed by username, where the `Instant` is the lockout expiry.
- **Runtime decisions use `std::time::Instant` exclusively** — never `SystemTime`, never wall-clock.
- The SQLite columns `users.failed_login_count` and `users.locked_until` remain as-is (ISO wall-clock timestamps) for **cross-restart durability only**.
- On process startup, hydrate the in-memory map from the DB: if `failed_login_count >= MAX_FAILED_ATTEMPTS` and `locked_until` is in the future per `SystemTime::now()`, seed `Instant::now() + remaining`. If already expired, clear.
- Lockout threshold stays at v1's value: **5 failed attempts**.

### Fernet key in Credential Manager (MUST-DO 1 — correct names)

v1's actual Credential Manager entry (verified against `app/crypto.py`):

- **`service = "DFARS Desktop"`** — exact string, space included, case-sensitive
- **`account = "totp_encryption_key"`** — exact string

**The earlier draft of this spec named `"dfars_desktop"/"fernet_key"` — THAT IS WRONG.** Using those names silently creates a new entry and renders ALL v1 encrypted data (TOTP secret, Agent Zero API key, SMTP password) permanently unreadable. SEC-1 flagged this as the most operationally dangerous finding in the review.

v2 `crypto.rs`:
- First try Rust `keyring` 2.x with the exact names above.
- Fallback: read `%APPDATA%\DFARS\.keyfile` (binary Fernet key) if keyring returns no result. Matches v1's fallback path.
- Third resort: generate a new key, write to keyring first and `.keyfile` as a backup.
- Log at INFO the key source used (`keyring` / `keyfile` / `new`) — **never log the key value itself**.
- **MUST (SEC-1 SHOULD-DO 6):** when the `.keyfile` path is used, surface a visible warning in the UI — NOT just a silent log line — via `settings_get_security_posture()` returning `{ keyring_active, mfa_enabled, recovery_codes_remaining }`.

### Fernet token compatibility — RESOLVED ✅

Round-trip test (Iteration 0, `v2/scratch/fernet_compat/RESULT.md`) confirmed: Python `cryptography` 45.0.7 and Rust `fernet` 0.2.2 (`rustcrypto` feature) round-trip byte-for-byte in both directions. **No AES-GCM migration needed.** v1 TOTP secrets, Agent Zero API keys, and SMTP passwords decrypt unchanged.

### Secrets decrypted by the v2 crypto module (OQ-1 + OQ-4)

A **single Fernet key** (the one in Credential Manager) protects **all** encrypted-at-rest secrets — this is intentional in v1 and preserved in v2:

1. TOTP secret (`users.totp_secret` column)
2. Agent Zero API key (`config.json` → `agent_zero_api_key_encrypted`)
3. **SMTP password** (`config.json` → `smtp_password_encrypted`) — **included in Phase 1 crypto module** (not deferred to Phase 5), so the first v2 launch for a user who has SMTP configured doesn't silently break email.

`crypto.rs` exposes `encrypt(&[u8]) -> String` and `decrypt(&str) -> Result<Vec<u8>>` generically; the three secret types above are just callers.

### Session management (OQ-2 + OQ-3 — design decisions locked in)

v1 uses Flask session cookies with a persistent session secret in `%APPDATA%\DFARS\session.key`. **v2 drops this entirely.**

- **Token transport (OQ-2):** `auth_login` and `auth_verify_mfa` return a plaintext session token as part of their `SessionInfo` payload. The React frontend stores it in **`sessionStorage` + React state**, NOT an HTTP cookie. This avoids all ambiguity about cookie lifetime, `HttpOnly`, and JS accessibility inside the Tauri WebView. Every subsequent Tauri command takes the token as its first parameter; `require_session()` validates.
- **Session lifetime (OQ-3):** sessions live in an in-memory `HashMap<String, SessionData>` in `AppState`. **No persistence across app restarts** — closing and relaunching the app requires a fresh login. This is a deliberate security improvement from v1's 7-day persisted sessions, aligned with NIST SP 800-63B §7.2. UX cost: one extra login per app launch. Accepted.
- Session data includes username, MFA status (`Verified` vs `Pending`), created-at `Instant`, last-activity `Instant`, and (during enrollment) the pending TOTP secret.
- Inactivity timeout: 30 minutes of no activity → session expired, token rejected, frontend redirected to `/auth/login`.

### Mandatory session guard (MUST-DO 3)

`auth/session.rs` exports:

```rust
pub fn require_session(state: &AppState, token: &str) -> Result<SessionData, AppError>
```

This function **MUST** be the first call inside every Tauri command that reads or mutates any of:
- `chain_of_custody`, `evidence`, `hash_verification`, `tool_usage`, `analysis_notes`
- `entities`, `entity_links`, `case_events`
- `evidence_files`, `evidence_analyses`, `case_shares`
- `users`, `recovery_codes`, `api_tokens` (except login/setup flow)
- `config.json` mutations

A comment block at the top of `commands/mod.rs` documents this requirement and lists every table that demands a guard. QA adds a **negative test per command group** — with no/invalid token, every such command must return `AppError::Unauthorized`.

### API tokens (bearer auth for external callers)

- Plaintext token shown to the user exactly once at creation; only the Argon2id hash + first-12-char preview are persisted in `api_tokens`.
- **SHOULD (SEC-1 SHOULD-DO 4):** verification fast path uses `token_preview` (first 12 chars of plaintext) as the lookup index — reduces Argon2 verification calls from O(n) to O(1). `token_preview` is already displayed in the UI, so using it as a lookup key leaks no additional info.
- `dfars_` prefix preserved for GitHub/etc secret scanning.
- API tokens can only be created from an *already-authenticated* session — no bootstrap path.

### Single-user enforcement

Preserved from v1: `auth.create_user` refuses to create a second user. Enforced at the application layer, not the schema.

### Out-of-scope for Phase 1 (audit / follow-up)

- **SHOULD (SEC-1 SHOULD-DO 5):** v1's `auth_routes.py:379` hardcodes `C:/Users/jhenn/agent-zero/...` for the Agent Zero plugin auto-setup. This is a **v1 bug** that must not be ported. When Phase 5 ports `settings_set_agent_zero`, the plugin path must come from `config.json` with a sensible default, never a hardcoded absolute developer path.

## 8. Agent Zero integration

> **Revised 2026-04-13** after SEC-4/5 network review (see `docs/sec-4-5-network-review.md`). The original section undercounted Agent Zero call paths (omitted `forensic_analyze` and `analyze_evidence` entirely) and had no exfiltration controls.

### HTTP contract

- Plugin endpoints at `/api/plugins/_dfars_integration/dfars_<verb>`, `X-API-KEY` header with the Fernet-decrypted key from `config.json`.
- v2 `src-tauri/src/agent_zero.rs` holds a `reqwest::Client` (rustls) + base URL + decrypted API key wrapped in `zeroize::Zeroizing<String>` so it wipes on drop (SEC-4 SHOULD-DO 3).
- `is_configured()` gate preserved: returns false if URL missing, key blob missing, or key decryption fails.
- Plugin-side code on Agent Zero (`usr/plugins/_dfars_integration/`) does not change at all; still calls v2's REST API via the same bearer-token flow.

### Agent Zero URL allowlist (SEC-4 MUST-DO 6 — exfiltration control)

`agent_zero_url` is validated before any `reqwest` call:

- Accept `http://` scheme with host in `{localhost, 127.0.0.1, host.docker.internal}`
- Reject anything else unless `config.json` contains `allow_custom_agent_zero_url = true` AND the settings UI displays a persistent amber warning banner
- Custom-URL mode also writes an audit entry at WARN level on startup and on every Agent Zero call

Rationale: `agent_zero_url` is a freeform config field. Without an allowlist, a tampered config.json silently POSTs the complete case payload (PII, investigator names, evidence descriptions, hashes) to an attacker-controlled server on the next `ai_summarize_case` call. The allowlist is the primary exfiltration control for the entire AI surface.

### Outbound call timeout table (SEC-4 SHOULD-DO 2)

| Endpoint | Connect | Total | Response body limit |
|---|---|---|---|
| `dfars_enhance` | 10 s | 30 s | 16 KiB |
| `dfars_classify` | 10 s | 30 s | 8 KiB |
| `dfars_summarize` | 10 s | 120 s | 64 KiB |
| `dfars_analyze_evidence` | 10 s | 180 s | 128 KiB |
| `dfars_forensic_analyze` | 10 s | 300 s | 256 KiB |

Each call runs through a `bounded_body(resp, max_bytes) -> Result<Bytes, AppError::PayloadTooLarge>` helper so a mangled or malicious Agent Zero response can't OOM the app.

v1 used a flat 60 s timeout for enhance/classify and 120 s for summarize — these new per-endpoint values better match real LLM latency tails.

### Tauri command surface (4 AI commands + forensic analyze)

Four commands call Agent Zero from the Tauri side. Each is session-gated (`require_session()` as the first line), each is audit-logged, each logs the exact field list sent to Agent Zero so there's an investigator-visible record of what left the machine:

- `ai_enhance(token, text)` — rewrites a narrative description. 30 s timeout. Sends only the narrative text.
- `ai_classify(token, text)` — returns categorization JSON. 30 s timeout. Sends only the narrative text.
- `ai_summarize_case(token, case_id)` — executive summary + conclusion. **120 s timeout.** Sends the ENTIRE case payload including case header, tags, evidence, custody chains, hashes, tools, analysis notes. **SEC-4 SHOULD-DO 4:** one-time pre-call consent banner (`shown_ai_summarize_consent` flag in config.json) warning the investigator exactly which fields are about to leave the machine.
- `evidence_forensic_analyze(token, evidence_id, narrative)` — AI-enhanced evidence analysis. **300 s timeout.** Sends full evidence record + file download URLs (the plugin then calls back to DFARS's axum server to fetch the files). This is the most sensitive call — the largest data surface and the longest timeout.

### Data exfiltration surface — what each call sends

Audit-log the exact field list on every call. Investigator-visible so there's a paper trail of "what left the machine."

| Command | Fields sent |
|---|---|
| `ai_enhance` | `text` (narrative only) |
| `ai_classify` | `text` (narrative only) |
| `ai_summarize_case` | `case_id`, full case record, all evidence, all custody, all hashes, all tools, all analysis notes, all tags |
| `evidence_forensic_analyze` | `evidence_id`, evidence record, evidence files manifest (paths + sha256), dfars_api_token (for plugin callback) |

The `dfars_api_token` pass-through for `evidence_forensic_analyze` is intentional — Agent Zero can't authenticate to the DFARS axum server without a token, and per-call passing is equivalent to the pre-stored-in-AZ-config model. Confirmed acceptable per SEC-4/5 review OQ-SEC4-3.

## 9. Migration phases

Each phase ends with **the v1 app still runnable** and v2 built + smoke-tested. Frontend and backend land together per phase — no "backend-only" or "frontend-only" merges.

| Phase | Scope | Done when |
|---|---|---|
| **0** | Scaffold Tauri 2 + React 19 under `v2/`, wire tauri-specta, land empty sqlx migration matching v1 schema, get a green `cargo build` + `npm run tauri build`. No features. | `.msi` installer produces a runnable (but empty) window titled "DFARS Desktop v2". |
| **1** | Auth + MFA. `auth_*` commands, login/setup/MFA screens in React, v1 `auth.db` opens unchanged. | User can log into v2 with their existing v1 credentials and TOTP code. |
| **2** | Cases CRUD. Dashboard, case detail, case form, sqlx queries for `cases` + `case_tags`. | User can create, list, view, edit, delete a case in v2; the same case is visible in v1 if v1 is launched against the same DB. |
| **3** | Evidence + custody + hashes + tools + analysis. All CRUD flows on the case-detail page. Report preview + generation. | `case.$id.tsx` reaches feature parity with v1's `case_detail.html`. |
| **4** | Link analysis: entities, links, events, graph endpoint, crime-line endpoint, React visualizations (Cytoscape + vis-timeline). | `case.$id.link-analysis.tsx` matches v1's `link_analysis.html` outputs row-for-row on the same DB. |
| **5** | External REST API (axum), API tokens screen, Agent Zero client, AI helper commands, drive scan, file upload + forensic analyze. | v1 Agent Zero plugin pushes into v2 successfully; `ai_summarize_case` returns a non-empty report. |
| **6** | Packaging: `tauri build` produces a signed `.msi`, `tauri-plugin-updater` wired to the same Ed25519 keys v1 uses, audit log writes to `%LOCALAPPDATA%\DFARS\Logs\`. | New machine install from the .msi runs, logs in, creates a case, receives an auto-update notification when a signed manifest is served. |
| **7** | Cleanup: delete `app/` + `packaging/`, promote `v2/` to repo root, retag as `v2.0.0`, update README. | `git log --oneline` shows the "v2 promoted" commit; CI green. |

## 10. Data migration from existing v1 installs

v1 data lives at `%APPDATA%\DFARS\{forensics.db,auth.db,config.json,evidence_files/}`. v2 reads **the same paths**. No copy, no translation.

- **forensics.db**: schema byte-identical, v2 opens it.
- **auth.db**: schema byte-identical. Argon2 hashes + TOTP secrets verify unmodified (given the Fernet compat check in §7).
- **config.json**: additive fields only (no renames). v2 ignores unknown fields and fills in defaults for missing new ones.
- **evidence_files/**: paths stored in the DB are absolute → remain valid.
- **Keyring entry**: `service="DFARS Desktop", account="totp_encryption_key"` → both apps read it. (Corrected per SEC-1 review — earlier spec draft had the wrong names, see §7 for full context.)

**First v2 launch** runs `sqlx::migrate!` which is idempotent against the v1 schema (every `CREATE TABLE IF NOT EXISTS`). If the checksum of the embedded migration doesn't match what sqlx would expect of a fresh DB, v2 records the migration as already-applied rather than re-running it — i.e. we ship the initial migration with `-- sqlx: idempotent` and use `sqlx::migrate::Migrator::run_direct()` on legacy DBs.

**Rollback story**: v1 can re-open the DB at any point because v2 adds no new columns or tables until phase 7 at the earliest. If the user wants to go back mid-migration, they launch `DFARS Desktop.exe` (v1) and everything still works.

## 11. Packaging, signing, updates

> **Revised 2026-04-13** after SEC-8 packaging review. The original §11 had two factual errors: (a) it claimed v1's Ed25519 key was reusable in Tauri (it's PKCS8 PEM; Tauri uses minisign format — incompatible); (b) it assumed GitHub Releases hosting (repo is private; Tauri updater has no auth-header support for private-repo asset URLs). Both corrected below.

### Installer

- `tauri.conf.json` configures the **NSIS** bundler, app identifier `com.dfars.desktop`, icons, and a `plugins.updater` section. NSIS chosen over WiX per SEC-8 MUST-DO 3 / OQ-SEC8-1 because NSIS supports per-user install scope without admin elevation; WiX per-user mode requires custom fragments and more moving parts.
- NSIS install mode string is **`"currentUser"`** (not `"perUser"` as an earlier draft said — Tauri 2's actual enum is `{"currentUser", "perMachine", "both"}`).
- **Install target: `%LOCALAPPDATA%\Programs\DFARS Desktop\`** — per-user, no UAC prompt. NOT `%ProgramFiles%` (which requires admin). Verify on a clean VM: `tauri build` → install → confirm no elevation prompt → confirm install path.
- v1's `installer.iss` with `PrivilegesRequired=admin` and `DefaultDirName={autopf}` is NOT replicated — those settings are explicitly wrong for v2's single-user model.

### Signing keys (SEC-8 MUST-DOs 1 + 2)

- **A new minisign-format Ed25519 key pair is generated with `cargo tauri signer generate -p`** (`-p` adds a passphrase — SEC-8 SHOULD-DO 1). The v1 PKCS8 key at `packaging/release_private_key.pem` is NOT reused — Tauri's updater requires minisign format and the conversion path is error-prone enough to risk silently broken signature verification.
- **Private key location: `%USERPROFILE%\.dfars-release\tauri-signing-key.key`** — OUTSIDE the repo tree, ACL-hardened:
  ```
  icacls %USERPROFILE%\.dfars-release /inheritance:r
  icacls %USERPROFILE%\.dfars-release /grant:r "%USERNAME%:(OI)(CI)F"
  ```
  Expected verify: `icacls` output shows only `<current-user>:(F)` — no `SYSTEM`, no `Administrators`.
- **Public key**: embedded in `tauri.conf.json` under `plugins.updater.pubkey` as the minisign public key string (not a PEM). Not sensitive — committed with the repo.
- **Consequence of new key**: v1 installs cannot auto-update to v2 via the updater. Acceptable for a single-user tool — user performs a one-time manual install of v2.0.0 via the NSIS MSI, then v2.x updates flow through the Tauri updater automatically once update hosting is set up.

### Auto-update hosting — DEFERRED to post-v2.0.0 (OQ-SEC8-3 resolution)

The GitHub repo is private. The Tauri updater plugin fetches release assets via plain HTTPS GET with no auth header support, so it cannot pull from private-repo release URLs. Rather than make the repo public or provision external hosting, v2.0.0 ships with:

- **The updater plugin wired in `tauri.conf.json`** but with a placeholder `endpoints = ["https://updates.dfars-desktop.invalid/latest.json"]` that returns an unreachable host.
- **Manual "Check for updates" button in `settings/security.tsx`** (NOT a launch-time auto-check, per OQ-SEC8-2 resolution — a forensic tool should not produce unexpected outbound traffic on every launch). When the user clicks it, the updater hits the placeholder endpoint and surfaces a friendly "Update server not configured — download updates manually from the GitHub Releases page" message.
- **New Ed25519 minisign keypair generated + ACL-hardened in Phase 6** anyway, stored for future use when the user picks a hosting story (Cloudflare R2, public-releases-repo, or making the main repo public). Phase 6 includes a working `cargo tauri build` that produces `latest.json` + `.sig` files alongside the MSI so the release workflow is ready to go when hosting lands.

**When auto-update hosting is eventually set up** (a 6.1 or 7.x task), the flow is:
1. Run `cargo tauri build` — produces MSI + `.sig` + `latest.json`
2. Upload those three files to the chosen host (R2 bucket or public release repo)
3. Update `plugins.updater.endpoints` in `tauri.conf.json` to point at the real URL
4. Rebuild + release v2.1.0 so it contains the updated endpoint
5. Users on v2.0.0 will need to manually install v2.1.0 one time (the v2.0.0 updater endpoint is unreachable); subsequent versions auto-update normally

### Update check UX

- **Manual-only** per OQ-SEC8-2. No `checkOnStartup` flag set.
- "Check for updates" button lives in `settings/security.tsx` next to the existing MFA / API tokens / security posture sections.
- Button states: idle → spinner ("checking...") → one of {"up to date", "update available v{X}", "update server not configured"}.
- On "update available", show a Shadcn dialog with release notes (from `latest.json` body) + "Install and restart" / "Later" buttons. "Install and restart" invokes the Tauri updater's install flow.

### Audit log file (SEC-8 SHOULD-DO 4)

Phase 1 added `tracing-appender` to `Cargo.toml` but it's not yet wired. Phase 6 wires it:

- **Location**: `%LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log`
- **Rotation**: size-based rolling, 10 MB per file, keep 5 most recent → 50 MB max disk usage
- **Mode**: `tracing_appender::non_blocking` so the Tauri main thread never blocks on log I/O (the drop guard is held by `AppState`)
- **Filter**: `tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))` — honors `RUST_LOG` env var at launch, defaults to INFO level for the app's own crate and WARN for dependencies
- **Directory creation**: `fs::create_dir_all(&log_dir)` at startup before any `tracing::info!` call
- **Subscriber setup**: runs in `lib.rs::run()` BEFORE `tauri::Builder::default()` so every tracing macro gets captured
- **Redaction requirements** (hard — enforced via code review):
  - Never log plaintext passwords, session tokens, API tokens, Fernet keys, TOTP secrets, recovery codes
  - Never log full case payloads, evidence file contents, or narrative text bodies
  - Never log filesystem paths beyond the top-level directory (`%APPDATA%\DFARS\...` is fine; individual case/evidence file paths are not)
  - DO log: command names, HTTP method + path for axum routes, error variants, durations, counts, usernames (they're already in the audit trail), timestamps

Separate from the file-based `dfars-desktop.log`, the existing pipe-delimited audit trail files (`auth_audit.txt`, `case_audit.txt`, etc.) from Phase 1 continue to exist for chain-of-custody defensibility. Two logs, two purposes — `.log` is for debugging, `.txt` audit files are the legal record.

### Code signing (Authenticode) — KNOWN GAP

Both v1 and v2 ship unsigned. Windows SmartScreen will flag first-time installers with the "Windows protected your PC" dialog until the installer accumulates enough reputation to clear it. Documented in the user-facing README as a known risk:

> **First install will trigger a SmartScreen warning.** Click "More info" → "Run anyway". The installer is legitimate; it's unsigned because Authenticode certificates cost $100–400/year and this is a personal forensics tool. Subsequent launches are not affected.

Revisit if/when the user decides to pursue an EV certificate.

### Bundle size optimization (Phase 6 polish)

Current main bundle is 2,097 KB raw / 637 KB gzip (as of Phase 5). Vite's 500 KB advisory is firing. Phase 6 splits the heavy routes via `React.lazy`:

- `case.$caseId.link-analysis.tsx` → lazy-load (Cytoscape ~300 KB + vis-timeline ~600 KB are only needed on this route)
- `components/report-dialog.tsx` → lazy-load (react-markdown + remark-gfm ~200 KB only needed when opening a report preview)
- `routes/settings/integrations.tsx` → lazy-load (Agent Zero + SMTP forms, rarely visited)

Target: main bundle under 1 MB raw / 300 KB gzip after splitting. Remaining chunks load on route navigation. No user-facing latency impact on the common path (login → dashboard → case detail).

## 12. Testing

- **Rust unit tests** (`cargo test`): per-module under `src-tauri/src/*/tests.rs`. Pure-function coverage of auth, crypto, query helpers.
- **Rust integration tests** (`src-tauri/tests/`): spin up a tokio runtime, build an `AppState` against a temp-dir sqlite, run command functions directly. Covers every `#[tauri::command]` without WebView in the loop.
- **Frontend unit tests** (Vitest): component tests for forms, hooks, TanStack Query cache invalidation logic.
- **E2E** (tauri-driver + WebDriverIO): one happy-path test per phase (login → create case → add evidence → generate report → logout). Runs on CI against the built `.msi`.
- **Schema drift guard**: CI fails if `.sqlx/` offline cache is out of date with the migrations + code.

## 13. Open questions

**Resolved 2026-04-12 (Iteration 0 kickoff):**

1. ✅ **Fernet compatibility — IN PROGRESS.** Test authorized; polyglot-software-engineer running a 30-min compat test (scratch dir `v2/scratch/fernet_compat/`). Result drives whether v1 encrypted secrets need AES-GCM rewrap on first v2 launch. Answer expected before Iteration 0 closes.
3. ✅ **Router = TanStack Router.** Confirmed. File-based, type-safe, integrates with TanStack Query.
4. ✅ **UI = Shadcn/UI + Tailwind.** Confirmed. Components live in-repo (no version-churn risk — critical for a long-lived forensics app that must produce identical exports years from now), Radix a11y, tiny bundle, matches v1's "vendor everything" policy.

**Still deferred:**

2. ✅ **axum vs. dropping the external REST API — RESOLVED.** Agent Zero plugin audit (`dfars_client.py` + `dfars_forensic_analyze.py`) confirmed all 12 v1 endpoints are in active use. "Minimal surface" and "full port" collapse to the same 12 endpoints. Port all 12 with SEC-4/5 constraints applied per §6 External REST API.
5. **Graph library: Cytoscape.js vs. sticking with vis-network.** Vis-network is what v1 uses; porting saves UI work but keeps an unmaintained dependency. Decide before phase 4.

## 14. Milestones and dependencies

- **MSVC + Windows SDK working.** Non-negotiable: Rust's MSVC toolchain on Windows needs `link.exe`, `ucrt`, and the Windows SDK headers. The current VS 18 Community install is incomplete (vcvarsall.bat missing, no `include/`, no Windows Kits 10). Phase 0 cannot start until the install is repaired.
- **Rust 1.80+ and Node 20+ installed.** Verify at phase 0.
- **`cargo install tauri-cli --version '^2.0'`** — required for `cargo tauri build`.
- **`.sqlx/` offline schema generated** — required for CI.

## 15. What this spec does *not* commit to

- Exact file-by-file implementation. That's decided inside each phase PR.
- The specific React component hierarchy. Phase 2 draws the first real one against real screens.
- Any schema *changes* v2 might eventually want. Those go in separate migrations after phase 7.
- Anything about a "v3." Not on the roadmap.

---

**Status:** Draft, 2026-04-12. Review before starting phase 0 scaffolding. All decisions in §13 must be resolved (even if the answer is "defer to phase N").
