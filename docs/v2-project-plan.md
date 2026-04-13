# DFARS Desktop v2 — Project Management Plan

> **PM Owner:** Software Project Manager agent  
> **Plan Date:** 2026-04-12  
> **Status:** Active — replace this header when a phase completes  
> **Source of truth for scope:** `docs/v2-migration-spec.md`  
> **This document owns:** schedule, decisions, risks, delegation, and metrics

---

## 1. Executive Summary

DFARS Desktop v2 is a ground-up rebuild of a single-user Windows forensics application from Python/Flask + PyWebView to Tauri 2 + Rust + React 19. v1 stays live throughout the rebuild — there is no cutover until full parity is confirmed at Phase 7. The rebuild spans 8 phases (0–7) estimated at 16–20 weeks of part-time, focused effort by a single developer + AI pair, targeting a v2.0.0 tag by **mid-August 2026**. The top three risks are: (1) MSVC toolchain repair remaining blocked, preventing any Rust compilation; (2) Fernet crypt incompatibility between Python and Rust requiring an emergency migration path before Phase 1 ships; and (3) schema drift between v1 and v2 during parallel development corrupting the shared production database.

---

## 2. Sprint / Iteration Breakdown

Each iteration is **2 weeks**. Single-developer pace: estimate 8–12 productive hours per week (part-time, focused). Each iteration has one and only one stop-ship criterion — if it is not met, the iteration extends by one week (max one extension per iteration before escalation).

### Iteration 0 — Environment & Scaffold Gate (Weeks 1–2: 2026-04-12 to 2026-04-25)

**Goal:** Phase 0 complete. Rust builds. Empty window shows. All 5 open questions decided.

| Task | Owner Agent | Notes |
|---|---|---|
| Verify / complete MSVC repair | User + polyglot-software-engineer | See MSVC fallback plan §3 below |
| Run `cargo build` in `v2/src-tauri/` | polyglot-software-engineer | First Rust compile gate |
| Wire tauri-specta in `build.rs` | polyglot-software-engineer | Generates `bindings.ts` on build |
| Land `0001_init.sql` sqlx migration | polyglot-software-engineer | Byte-identical to v1 schema DDL |
| Generate `.sqlx/` offline cache | polyglot-software-engineer | Required for CI |
| Decide all 5 open questions (§4 below) | User — deadlines set | Defaults kick in if no response by 2026-04-16 |
| `npm run tauri build` → `.msi` | polyglot-software-engineer | Produces empty titled window |
| Commit + push Phase 0 branch | User | Do not push v2 scaffold already on local main |

**Stop-ship criterion:** Running `npm run tauri build` produces a `.msi` that installs and shows a window titled "DFARS Desktop v2". `cargo build` green. `npm run build` green.

---

### Iteration 1 — Auth + MFA (Weeks 3–4: 2026-04-26 to 2026-05-09)

**Goal:** Phase 1 complete. User logs into v2 with existing v1 credentials and TOTP.

| Task | Owner Agent |
|---|---|
| Implement `auth_*` Rust commands (argon2, totp-rs, session, keyring) | polyglot-software-engineer |
| Fernet compat verified + crypto path finalized | polyglot-software-engineer |
| Login / setup / MFA screens in React | fullstack-dev-builder |
| Shadcn/UI component shell wired | gui-cx-designer |
| Security review: auth implementation | security-compliance-auditor |
| Rust unit tests: argon, totp, session | qa-testing-engineer |
| E2E smoke: login → dashboard → logout | qa-testing-engineer |

**Stop-ship criterion:** Existing v1 credentials + TOTP code authenticate successfully in v2. Recovery code flow works. Lockout after 5 bad attempts enforced.

**Security gate:** security-compliance-auditor sign-off required before iteration closes (see §6).

---

### Iteration 2 — Cases CRUD (Weeks 5–6: 2026-05-10 to 2026-05-23)

**Goal:** Phase 2 complete. Cases created in v2 are visible in v1 against the same DB.

| Task | Owner Agent |
|---|---|
| `cases_*` sqlx queries + Tauri commands | polyglot-software-engineer |
| Dashboard + case list + case form + case detail routes | fullstack-dev-builder |
| TanStack Query cache invalidation on mutations | fullstack-dev-builder |
| Rust integration tests: cases CRUD via ephemeral SQLite | qa-testing-engineer |
| Vitest: form validation + query hooks | qa-testing-engineer |

**Stop-ship criterion:** Create/list/view/edit/delete a case in v2. Open v1 against same `%APPDATA%\DFARS\forensics.db` — same case visible. No data loss.

---

### Iteration 3 — Evidence, Custody, Reports (Weeks 7–9: 2026-05-24 to 2026-06-13)

**Goal:** Phase 3 complete. Case detail page reaches feature parity with v1.

Three weeks allocated (scope is largest: evidence CRUD + chain-of-custody + hash verification + tool usage + analysis notes + report generation).

| Task | Owner Agent |
|---|---|
| `evidence_*`, `custody_*`, `hash_*`, `tool_*`, `analysis_*` commands | polyglot-software-engineer |
| File upload + `evidence_files` table + sha256 verification | polyglot-software-engineer |
| Report markdown generator (port of `report_generator.py`) | polyglot-software-engineer |
| Case detail page: all sub-panels | fullstack-dev-builder |
| Report preview + generation UI | fullstack-dev-builder |
| Security review: file upload handling | security-compliance-auditor |
| Integration tests: evidence lifecycle | qa-testing-engineer |
| E2E: login → case → add evidence → generate report | qa-testing-engineer |

**Stop-ship criterion:** `case.$id.tsx` matches v1's `case_detail.html` feature-for-feature against the same DB. Report PDF/markdown generated and saved.

---

### Iteration 4 — Link Analysis (Weeks 10–11: 2026-06-14 to 2026-06-27)

**Goal:** Phase 4 complete. Graph and crime-line views match v1 output row-for-row.

| Task | Owner Agent |
|---|---|
| `entities_*`, `links_*`, `events_*`, `case_graph`, `case_crime_line` commands | polyglot-software-engineer |
| Cytoscape.js integration (vendored, offline-safe) | fullstack-dev-builder |
| vis-timeline integration (kept from v1, vendored) | fullstack-dev-builder |
| Type-filter controls + graph layout | gui-cx-designer |
| Integration tests: graph payload shape | qa-testing-engineer |
| Cross-validation: same DB, v1 graph == v2 graph (node/edge count) | qa-testing-engineer |

**Stop-ship criterion:** Graph and crime-line in v2 produce identical node/edge counts and timeline entries as v1 on the same case DB. No vis-network dependency in v2.

---

### Iteration 5 — External API + Agent Zero + AI + Drives (Weeks 12–14: 2026-06-28 to 2026-07-18)

**Goal:** Phase 5 complete. Agent Zero plugin pushes to v2 successfully. AI summarize returns output.

Three weeks: largest backend surface (axum REST, API tokens, Agent Zero client, AI commands, drives).

| Task | Owner Agent |
|---|---|
| axum server in-process on tokio task | polyglot-software-engineer |
| Minimal REST surface: only endpoints Agent Zero actually calls (default decision — see §4 Q2) | polyglot-software-engineer |
| Bearer token auth on axum routes | polyglot-software-engineer |
| API tokens CRUD UI + commands | fullstack-dev-builder |
| `agent_zero.rs` reqwest client + decryption | polyglot-software-engineer |
| `ai_enhance`, `ai_classify`, `ai_summarize_case` commands | polyglot-software-engineer |
| `drives_list`, `drive_scan` commands | polyglot-software-engineer |
| Settings: Agent Zero URL + SMTP config screens | fullstack-dev-builder |
| Security review: axum API surface + bearer token implementation | security-compliance-auditor |
| Security review: Agent Zero API key decryption path | security-compliance-auditor |
| AI integration test: Agent Zero plugin round-trip | ai-ml-integration-architect + qa-testing-engineer |
| Audit log: `share_record`, `audit_tail` | polyglot-software-engineer |
| Security review: audit log integrity | security-compliance-auditor |

**Stop-ship criterion:** v1 Agent Zero plugin (`_dfars_integration`) calls v2 REST API with bearer token and gets valid responses. `ai_summarize_case` returns a non-empty report. `audit_tail` shows entries.

---

### Iteration 6 — Packaging + Signing + Updater (Weeks 15–16: 2026-07-19 to 2026-08-01)

**Goal:** Phase 6 complete. Signed `.msi` installs on a clean machine and receives an update.

| Task | Owner Agent |
|---|---|
| `tauri build` configured for MSI output | polyglot-software-engineer |
| Ed25519 keys reused from `packaging/keygen.py` | polyglot-software-engineer |
| `tauri-plugin-updater` + `latest.json` served from GitHub Releases | polyglot-software-engineer |
| Audit log writes to `%LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log` | polyglot-software-engineer |
| Final security review: installer + updater + Authenticode gap noted | security-compliance-auditor |
| Clean-machine install test | qa-testing-engineer |
| E2E: install → login → case → update notification | qa-testing-engineer |

**Stop-ship criterion:** Fresh install from `.msi` on a clean Windows 11 machine: logs in, creates a case, receives an auto-update notification when a signed manifest is served. No SmartScreen false-positive escalation (note: Authenticode unsigned — document as known risk, not blocker).

---

### Iteration 7 — Parity Validation + Promotion (Weeks 17–18: 2026-08-02 to 2026-08-15)

**Goal:** Phase 7 complete. v2 is the repo root. v2.0.0 tagged.

| Task | Owner Agent |
|---|---|
| Full parity validation against v1 feature list | qa-testing-engineer |
| Data migration dry-run on real production DB | qa-testing-engineer |
| Delete `app/` + `packaging/` | polyglot-software-engineer |
| Promote `v2/*` to repo root | polyglot-software-engineer |
| Update top-level README | User |
| Tag `v2.0.0`, push | User |
| Final security sign-off | security-compliance-auditor |
| Post-mortem retrospective | PM + User |

**Stop-ship criterion:** `git log --oneline` shows "v2 promoted" commit. CI green. v1 codebase no longer present in repo root. `v2.0.0` tag visible on GitHub.

---

## 3. MSVC Blocker — Critical Path & Fallback

**Current status (2026-04-12):** VS 2019 Community installed but incomplete — no `include/`, no Windows Kits 10, no `vcvarsall.bat`. VS Installer GUI launched to add "Desktop development with C++" workload. Status unknown.

### Gate check (do this first, before anything else):

```powershell
# In a new terminal after VS Installer finishes:
& "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
# Should print: [vcvarsall.bat] Environment initialized...
cargo build --manifest-path C:\Users\jhenn\dfars-desktop\v2\src-tauri\Cargo.toml
```

### Fallback decision tree (in order — stop at first success):

| Option | Action | Cost | Risk |
|---|---|---|---|
| **A (preferred):** VS 2019 repair complete | Verify above command, proceed | Zero | None if VS install succeeded |
| **B:** Install VS 2022 Build Tools standalone | Download `vs_BuildTools.exe`, select "Desktop development with C++" — ~6 GB, no IDE | ~30 min | Low — well-tested Tauri path |
| **C:** Winget shortcut | `winget install Microsoft.VisualStudio.2022.BuildTools` then add workload via `--add Microsoft.VisualStudio.Workload.VCTools` | ~45 min | Low |
| **D:** GNU toolchain (mingw-w64) | `rustup toolchain install stable-x86_64-pc-windows-gnu`, reconfigure Tauri | Medium — some Windows-specific crates may not compile cleanly | Higher; not the default Tauri path on Windows |
| **E (last resort):** Build VM | Use a separate Windows 11 machine or VM with clean VS 2022 Build Tools for Phase 0 compilation only | Hours | Low; no local dev convenience |

**Rule:** Try A first. If `cargo build` fails by end of day 2026-04-12, execute B immediately. Do not attempt GNU toolchain (D) unless B and C both fail — MSVC is strongly preferred for Windows system calls in Rust.

**Owner:** polyglot-software-engineer to diagnose and execute. User approves fallback escalation past B.

---

## 4. Decision Gates — 5 Open Questions

All five decisions must be made by **2026-04-16** (end of Iteration 0, Week 1). If the user has not decided, the default kicks in automatically. Defaults are chosen to minimize rework and match spec intent.

| # | Question | Deadline | Default if no response | Who decides |
|---|---|---|---|---|
| Q1 | Fernet compat: Rust `fernet` crate round-trips Python `cryptography.fernet` tokens? | 2026-04-16 | **Assume incompatible.** Plan one-shot AES-GCM migration on first v2 launch. polyglot-software-engineer runs a 30-minute compat test during Phase 0 and reports. | polyglot-software-engineer tests; User confirms migration plan |
| Q2 | axum REST API scope: full 15-endpoint port vs. minimal Agent Zero surface (~5 endpoints) | 2026-04-16 | **Minimal surface only.** Audit Agent Zero plugin (`_dfars_integration`) to identify exactly which endpoints it calls; port only those for Phase 5. Full port deferred to v2.1 if ever needed. | ai-ml-integration-architect audits plugin; User approves scope cut |
| Q3 | TanStack Router vs. React Router 6 | 2026-04-14 (earlier — route files start in Iteration 1) | **TanStack Router** (spec default). Already listed in spec §3; file-based type-safe routing fits tauri-specta codegen. Do not switch without explicit user override. | User decides by 2026-04-14; default locks in automatically |
| Q4 | UI library: Shadcn/UI + Tailwind vs. MUI/Chakra | 2026-04-14 (earlier — components start in Iteration 1) | **Shadcn/UI + Tailwind** (spec default). Vendorable, offline-safe, accessible. MUI requires CDN or heavier bundle — incompatible with offline forensics use case. | User decides by 2026-04-14; default locks in automatically |
| Q5 | Graph library: Cytoscape.js vs. keep vis-network | 2026-04-16 | **Cytoscape.js** (spec default). vis-network is unmaintained; Cytoscape is actively maintained and has better perf at 500+ nodes. Port effort is one iteration (Phase 4). | User decides by 2026-04-16 |

**Process:** PM agent opens each question with the user at the start of Iteration 0. If no response by the deadline, the default is recorded in this document and work proceeds. No re-litigation after the iteration that uses the decision starts.

---

## 5. Risk Register

| # | Risk | Likelihood | Impact | Score | Mitigation | Owner | Review |
|---|---|---|---|---|---|---|---|
| R1 | MSVC toolchain repair fails; `cargo build` stays broken | Medium | Critical — blocks all Rust work | HIGH | Fallback decision tree §3: B/C/D in order. Time-boxed: if not resolved by 2026-04-14, execute B immediately. | polyglot-software-engineer | Daily during Iteration 0 |
| R2 | Rust `fernet` crate incompatible with Python tokens; TOTP secrets and Agent Zero API keys cannot decrypt | High | Critical — Phase 1 cannot ship without a decryption path for existing keys | HIGH | Default: assume incompatible, build one-shot AES-GCM migration during Phase 0 test. Verify with a 30-min compat test using a v1-produced token + the same key. | polyglot-software-engineer | Phase 0 gate |
| R3 | Schema drift: v1 and v2 both write to shared `%APPDATA%\DFARS\forensics.db` during parallel dev; v2 migration adds a column v1 doesn't expect | Medium | High — could corrupt production DB for the one real user | HIGH | Strict rule: v2 adds NO new columns or tables until Phase 7. All v2 sqlx migrations through Phase 6 are idempotent against v1 schema only. security-compliance-auditor reviews each migration file before it ships. | polyglot-software-engineer + PM | Every migration PR |
| R4 | Agent Zero integration break: v2 REST API (axum) diverges from v1 contract; plugin stops working | Low (if we're disciplined) | High — breaks the AI summarize workflow the user relies on | MEDIUM | Explicitly audit v1 `/api/v1/*` routes vs. Agent Zero plugin calls before Phase 5. axum routes must be byte-compatible with v1 (same paths, same JSON shapes). ai-ml-integration-architect owns the audit. Integration test: Agent Zero plugin round-trip in CI. | ai-ml-integration-architect | Phase 5 gate |
| R5 | Data migration failure: v2 first launch against real production DB fails or corrupts data | Low | Critical — chain-of-custody data is legally significant | HIGH | Mandatory dry-run in Phase 7 against a copy of the real DB before promoting. Backup `%APPDATA%\DFARS\` before first v2 launch. sqlx migration is idempotent. Rollback to v1 stays viable until Phase 7 commit. | qa-testing-engineer | Phase 7 gate |
| R6 | Scope creep: v2 spec grows during the rebuild (new features requested) | Medium | Medium — extends timeline, risks parity focus | MEDIUM | Strict change control. Any new feature goes into a "v2.1 backlog" doc. Nothing enters Phase 0–7 scope without PM sign-off and explicit timeline impact assessment. | PM | Every iteration |
| R7 | Authenticode code signing gap: `.msi` unsigned; Windows SmartScreen blocks end-user installs | High (SmartScreen fires) | Medium — known from v1, not new; single user so impact limited | LOW | Document as known risk, same as v1. Flag to user at Phase 6 gate with cost of acquiring an Authenticode cert ($100–400/yr EV cert). Not a blocker for Phase 6 stop-ship. | PM + User | Phase 6 |
| R8 | tauri-specta codegen breaks on type mismatch; `bindings.ts` out of sync with Rust commands | Medium | Medium — causes TS build failures; caught quickly in dev | LOW | CI enforces that `npm run build` passes after every Rust change. `build.rs` re-runs specta on every cargo build. Any type mismatch is a build error, not a runtime error. | polyglot-software-engineer | Every PR |
| R9 | Part-time pace slippage: user unavailable for extended period; iterations slide | Medium | Low-Medium — timeline extends but v1 still runs | LOW | Each iteration has a maximum 1-week extension before PM escalates for scope cut or reprioritization. v1 stays live — no user-facing degradation during slippage. | PM | End of each iteration |

---

## 6. Security Review Coordination Plan

**Security agent:** security-compliance-auditor  
**Mandate:** Forensic evidence application. Chain-of-custody records are legally significant. May touch PII, PHI (if cases involve medical evidence), and law-enforcement-sensitive data. Standards applicable: NIST SSDF, OWASP ASVS (Level 2), NIST 800-171 (controls relevant to CUI handling in forensic context), NIST AI RMF (for AI-assisted reporting features).

### Review schedule

| Review | Trigger | Scope | Blocking? |
|---|---|---|---|
| **SEC-1: Auth architecture review** | Before Iteration 1 work starts (2026-04-26) | Argon2id parameter match with v1, TOTP parameter match, session management design (in-memory HMAC cookie vs. persisted secret), lockout implementation, recovery code design | YES — Iteration 1 cannot start without SEC-1 approval |
| **SEC-2: Fernet/crypto migration review** | During Iteration 1 (before merging crypto module) | Fernet → AES-GCM migration plan if Fernet compat fails; key derivation; keyring integration; no hardcoded secrets | YES — crypto module merge blocked on SEC-2 |
| **SEC-3: File upload handling review** | During Iteration 3 (before evidence upload ships) | Path traversal prevention on `evidence_files_upload`; sha256 verification implementation; storage path validation; MIME type handling | YES — file upload command blocked on SEC-3 |
| **SEC-4: axum API surface review** | Before Iteration 5 work on axum starts | Bearer token validation implementation; bind_host controls (127.0.0.1 vs 0.0.0.0); rate limiting; input validation on all axum routes; CORS posture | YES — axum routes blocked on SEC-4 |
| **SEC-5: Agent Zero API key decryption review** | During Iteration 5 (before agent_zero.rs merges) | Decrypted API key handling in memory; no logging of plaintext keys; reqwest TLS validation; timeout enforcement | YES — agent_zero.rs merge blocked on SEC-5 |
| **SEC-6: Audit log integrity review** | During Iteration 5 (before audit_tail ships) | Audit log append-only posture; no log injection; tamper-evidence considerations for chain-of-custody legally significant events | YES — audit commands blocked on SEC-6 |
| **SEC-7: Migration file review** | Every new sqlx migration before merge | Schema change does not break v1 compat; no accidental column drops; FK RESTRICT enforcement preserved on custody tables | YES — any migration PR blocked on SEC-7 |
| **SEC-8: Packaging + updater review** | Iteration 6 start | Ed25519 key reuse validation; updater manifest integrity; installer permissions; no private key in repo; Authenticode gap documented | YES — Phase 6 sign-off blocked on SEC-8 |
| **SEC-9: Final pre-release review** | Phase 7 gate | Full surface review: auth, crypto, API, file handling, audit log, updater. Sign-off document produced. | YES — v2.0.0 tag blocked on SEC-9 |

### How findings flow back

1. security-compliance-auditor produces a findings list: severity (P0/P1/P2/P3), affected component, recommended fix.
2. P0 findings: halt the blocked work immediately. PM and polyglot-software-engineer triage within 24 hours. No merge until resolved.
3. P1 findings: must be resolved before the iteration closes.
4. P2/P3 findings: logged in a "Security Debt" section appended to this document. Addressed in the next iteration or before v2.0.0, whichever is sooner.
5. PM records all security reviews and their outcomes in the iteration retrospective.

---

## 7. Agent Delegation Matrix

| Agent | Primary Ownership | When to Invoke |
|---|---|---|
| **polyglot-software-engineer** | All Rust/backend work: commands, sqlx queries, axum, crypto, agent_zero.rs, migrations, tauri-specta wiring, packaging scripts | Every iteration — this agent does the majority of the implementation work |
| **fullstack-dev-builder** | All React/frontend work: routes, components, TanStack Query, TanStack Router, forms, bindings.ts consumption | Iterations 1–6; works in parallel with polyglot-software-engineer where possible |
| **gui-cx-designer** | Shadcn/UI component design, layout, UX parity with v1, accessibility review | Iterations 1, 2, 4 (graph UI); spot-reviewed in 3 and 5 |
| **qa-testing-engineer** | Rust unit + integration tests, Vitest component tests, E2E via tauri-driver, parity validation, clean-machine install | Every iteration; owns stop-ship verification |
| **security-compliance-auditor** | All security reviews (SEC-1 through SEC-9); findings triage | Per schedule in §6; never skipped |
| **ai-ml-integration-architect** | Agent Zero plugin audit (Q2 decision), AI command design review, integration test for Agent Zero round-trip | Iteration 0 (Q2 audit), Iteration 5 (AI commands + integration) |
| **lead-architect** | Escalation on architectural disputes: if TanStack Router, Shadcn, or axum design choices produce implementation dead-ends | On-call; invoke if polyglot-software-engineer flags a structural blocker |
| **data-science-specialist** | Not in scope for v2.0.0 rebuild. Invoke post-v2.0.0 if AI/ML model integration expands beyond Agent Zero pass-through | Post-v2.0.0 |
| **PM (this agent)** | Sprint planning, decision gate enforcement, risk tracking, retrospectives, security coordination, change control | Every iteration boundary + on-demand when blockers surface |

---

## 8. Milestone Calendar

| Milestone | Target Date | Gate Criteria |
|---|---|---|
| M0: MSVC resolved; `cargo build` green | 2026-04-14 | `cargo build` exits 0 in v2/src-tauri/ |
| M0.1: All 5 open questions decided | 2026-04-16 | Decisions recorded in §4 of this document |
| M1: Phase 0 complete | 2026-04-25 | `.msi` installs, empty window shows, specta wired, migration in place |
| M2: Phase 1 complete — Auth parity | 2026-05-09 | v1 credentials + TOTP log into v2; SEC-1 + SEC-2 signed off |
| M3: Phase 2 complete — Cases CRUD | 2026-05-23 | Cross-DB case visibility confirmed |
| M4: Phase 3 complete — Evidence + Reports | 2026-06-13 | Case detail parity; report generation works; SEC-3 signed off |
| M5: Phase 4 complete — Link Analysis | 2026-06-27 | Graph + crime-line parity confirmed |
| M6: Phase 5 complete — API + AI | 2026-07-18 | Agent Zero round-trip green; SEC-4 + SEC-5 + SEC-6 signed off |
| M7: Phase 6 complete — Packaging | 2026-08-01 | Clean-machine install + update notification; SEC-8 signed off |
| M8: v2.0.0 — Phase 7 + Promotion | 2026-08-15 | Repo root is v2; tag pushed; SEC-9 signed off |

**Buffer assumption:** 16 weeks of planned work + 2 weeks of float for iteration extensions and MSVC/Fernet surprises. If MSVC repair takes more than 3 days, the float absorbs it without moving the end date.

---

## 9. Retrospective Cadence and Success Metrics

### Retrospective schedule

- **Per-phase mini-retro:** At each phase stop-ship gate. 15 minutes. Three questions: (1) What slowed us down? (2) What worked? (3) One concrete action for next iteration. PM records outcomes in this doc under "Retro Notes" appendix.
- **Mid-point retro (after Phase 3):** Deeper review at M4. Review estimate accuracy, risk register currency, security debt backlog. Adjust timeline if needed.
- **Post-project retro (after Phase 7):** Full project retrospective. Review all risks that materialized, estimation accuracy, agent delegation effectiveness.

### Metrics tracked per iteration

| Metric | Target | How Measured |
|---|---|---|
| Commands ported (Tauri `#[tauri::command]`) | 100% of ~50 by Phase 5 | Count in `commands/` modules |
| Rust unit test coverage | >80% of non-trivial functions by Phase 3 | `cargo tarpaulin` or `llvm-cov` |
| Frontend component test coverage | >70% of form + hook logic by Phase 3 | Vitest coverage report |
| E2E happy-path tests passing | 1 per phase, cumulative | tauri-driver test suite |
| Build time: `cargo build` (incremental) | Under 60s by Phase 2 (after initial compile cache warms) | Timed in CI |
| Security findings: P0/P1 open at phase gate | 0 (hard gate) | SEC-N review outcomes |
| Phase stop-ship criterion met on first attempt | Target: 6 of 8 iterations | Retrospective tracking |
| Schema drift incidents | 0 | SEC-7 migration reviews |

### DORA metric goals (aspirational for a single-dev project)

- **Deployment frequency:** One tagged release per phase (8 total).
- **Lead time for changes:** Code-to-merged under 48 hours for any single task.
- **Change failure rate:** Zero data-corrupting changes (chain-of-custody tables are hard stop).
- **MTTR:** Any build breakage fixed within one working day.

---

## 10. Assumptions

The following assumptions were made without explicit confirmation from the user. Correct any that are wrong — the plan will be adjusted.

| # | Assumption | Impact if Wrong |
|---|---|---|
| A1 | User is working 8–12 hours/week on this project (part-time, focused) | If fewer hours: extend milestone calendar by 1 week per 2 hours/week below baseline. If more: could compress by 2–3 weeks. |
| A2 | The single real user of v1 is the owner (the user themselves) — no other people are depending on v1 staying stable during the rebuild | If other users exist: v1 freeze discipline becomes more critical; add a "v1 emergency patch" protocol |
| A3 | GitHub Actions (or similar CI) will be configured for v2 builds — the spec mentions CI but no CI provider is named | If no CI: test gates rely entirely on local runs; adjust SEC-7 migration review process |
| A4 | The Ed25519 private key from `packaging/keygen.py` is available and backed up — Phase 6 depends on it | If lost: must regenerate; loses the ability to push updates to any existing v1 installs |
| A5 | Agent Zero container is available for integration testing in Phase 5 — the `_dfars_integration` plugin is installed and the container is reachable at `host.docker.internal` | If not available: Phase 5 integration test uses a mock; real round-trip deferred to Phase 6 smoke test |
| A6 | Fernet compat test (Q1) will be run as a standalone Rust + Python script during Phase 0, not requiring a full `cargo build` to complete first | If compat test requires a full Rust build: MSVC blocker must be resolved before Q1 can be answered; Iteration 1 planning assumes AES-GCM migration path by default |
| A7 | "Minimal REST surface" for axum (Q2 default) means the ~5 endpoints the Agent Zero `_dfars_integration` plugin actually calls — ai-ml-integration-architect will audit the plugin code to confirm the exact list | If plugin calls more endpoints than expected: Phase 5 scope increases; flag immediately |
| A8 | Shadcn/UI and TanStack Router are the confirmed defaults (Q3 + Q4) unless the user overrides by 2026-04-14 — frontend work in Iteration 1 begins on that assumption | If user wants MUI or React Router: all Iteration 1 frontend work must restart; push frontend start to 2026-04-28 |
| A9 | v2 will not be code-signed with Authenticode in v2.0.0 — same gap as v1 | If user acquires an Authenticode cert mid-project: integrate into Phase 6 packaging; no timeline impact if cert arrives before 2026-07-19 |
| A10 | This is a private repo on GitHub; no public release artifact until the user decides to publish | If public release is intended: SEC-9 review must include supply-chain and artifact integrity review; add to Phase 7 scope |

---

## Appendix: Retro Notes

*(Populated at each phase gate — empty at plan creation.)*

---

## Appendix: Security Debt Backlog

*(P2/P3 findings from SEC reviews logged here — empty at plan creation.)*

---

## Appendix: Change Log

| Date | Change | Approved By |
|---|---|---|
| 2026-04-12 | Initial plan created | PM agent |
