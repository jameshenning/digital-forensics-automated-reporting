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
- `evidence_files_upload(evidence_id, file_path) -> EvidenceFile`
- `evidence_files_download(file_id) -> PathBuf`
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
Same routes as v1's `/api/v1/*`:
- `GET /api/v1/whoami`
- `GET /api/v1/cases`, `POST /api/v1/cases`
- `GET /api/v1/cases/<id>`, `PATCH /api/v1/cases/<id>`
- `POST /api/v1/cases/<id>/{evidence,custody,hashes,tools,analysis}`
- `GET /api/v1/cases/<id>/report`
- `GET /api/v1/cases/<id>/evidence/<eid>/files/<fid>/download`

This server runs in-process on a tokio task, using the same sqlx pool as the Tauri commands. `bind_host` from `config.json` controls whether it binds `127.0.0.1` or `0.0.0.0` (preserving v1's Agent Zero-in-Docker story).

## 7. Auth / MFA parity

- **Passwords.** v1 hashes are `$argon2id$v=19$m=...` encoded strings. The `argon2` crate's `PasswordHash::new` + `Argon2::default().verify_password` reads them directly. No rehashing on login.
- **TOTP.** v1 secrets are Base32, 6-digit, 30 s, SHA-1 (pyotp default). `totp-rs` with `Algorithm::SHA1`, `digits=6`, `step=30` matches byte-for-byte.
- **Recovery codes.** Same format as v1 (Argon2id hash per code). `recovery_codes` table unchanged.
- **Fernet key in Credential Manager.** v1 uses `keyring.set_password("dfars_desktop", "fernet_key", ...)`. Rust `keyring` crate hits the same Credential Manager entry under the same service/account names → v2 reads v1's stored key unchanged.
- **Fernet token compatibility.** v1 encrypts TOTP secrets + Agent Zero API keys with `cryptography.fernet`. Verify the Rust `fernet` crate round-trips v1-produced tokens with the same key; if not, add a one-shot migration that decrypts on first v2 launch using a vendored Python shim, re-encrypts with AES-GCM, and drops Fernet. **Decision point before implementation.**
- **Session secret.** v1 stores a persistent session secret in `%APPDATA%\DFARS\session.key`. v2 replaces this with an in-memory session map keyed by an HMAC cookie issued to the WebView on login. No persisted secret needed because Tauri commands authenticate the *active window* rather than arbitrary HTTP clients.

## 8. Agent Zero integration

- HTTP contract unchanged: plugin endpoints at `/api/plugins/_dfars_integration/dfars_<verb>`, `X-API-KEY` header.
- `src-tauri/src/agent_zero.rs` holds a `reqwest::Client` + base URL + decrypted API key.
- `is_configured()` gate preserved: returns false if URL missing, key blob missing, or key decryption fails.
- 120 s timeout on `ai_summarize_case` (matches v1).
- Plugin-side code on Agent Zero (`usr/plugins/_dfars_integration/`) does not change at all; still calls v2's REST API via the same bearer-token flow.

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
- **Keyring entry**: `service="dfars_desktop", account="fernet_key"` → both apps read it.

**First v2 launch** runs `sqlx::migrate!` which is idempotent against the v1 schema (every `CREATE TABLE IF NOT EXISTS`). If the checksum of the embedded migration doesn't match what sqlx would expect of a fresh DB, v2 records the migration as already-applied rather than re-running it — i.e. we ship the initial migration with `-- sqlx: idempotent` and use `sqlx::migrate::Migrator::run_direct()` on legacy DBs.

**Rollback story**: v1 can re-open the DB at any point because v2 adds no new columns or tables until phase 7 at the earliest. If the user wants to go back mid-migration, they launch `DFARS Desktop.exe` (v1) and everything still works.

## 11. Packaging, signing, updates

- `tauri.conf.json` configures the MSI bundler, app identifier `com.dfars.desktop`, icons, and the `updater` section.
- **Ed25519 keys are reused from v1** — `packaging/keygen.py` output already produced the public key that Tauri's updater expects (both use `ed25519-dalek`-compatible signatures). The private key stays out of the repo.
- **Code signing (Authenticode)** remains a known gap (same as v1); revisit once we have a cert.
- **Updater manifest**: Tauri's updater wants a `latest.json` hosted over HTTPS containing version + platform-specific URLs + Ed25519 signatures. We serve this from GitHub Releases for the first pass.

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

2. **axum vs. dropping the external REST API.** Agent Zero is the only known consumer. Worth considering: expose a *minimal* `axum` surface only for the endpoints Agent Zero actually calls (probably 4–5 of the 15), rather than porting the full `/api/v1/*` tree. *Owner: audit agent-zero plugin before phase 5.*
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
