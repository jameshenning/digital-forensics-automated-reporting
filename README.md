# DFARS Desktop

A single-user Windows desktop application for digital forensics case management and reporting. Built on Tauri 2 + Rust + React 19.

Current release: **v2.0.0**. The v1 Python/Flask implementation is preserved at the `v1-final` git tag for historical reference.

See `docs/v2-migration-spec.md` for the full architecture spec and `docs/sec-{1,3,4-5,8,9}-*.md` for the security review history.

## Features

- **Auth + MFA** — Argon2id passwords, TOTP via `totp-rs`, Argon2id-hashed single-use recovery codes, monotonic lockout timer
- **Case management** — create/edit/delete cases with tags, investigator, agency, classification, and evidence-drive-path
- **Evidence records** — evidence, chain of custody (with auto-assigned custody sequence per item), hash verifications, tool usage logs, analysis notes
- **File uploads** — streaming SHA-256 hash-while-write, filename sanitization with Unicode NFC normalization, canonicalize-check against path traversal, integrity re-verification on download, OneDrive sync warning
- **Link analysis** — entities, relationships, case events with a Cytoscape.js network graph and vis-timeline crime line
- **Reports** — markdown report preview and export via `react-markdown`
- **AI integration** — optional Agent Zero client for enhance/classify/summarize/forensic-analyze (30s/30s/120s/300s timeouts, URL allowlist, per-endpoint body caps, one-time consent banner)
- **External REST API** — 12-endpoint bearer-token `axum` server on `127.0.0.1:5099` for Agent Zero inbound pushes (timing-oracle mitigated, token-space isolated, per-route body limits, JSON depth guard)
- **Audit logging** — pipe-delimited chain-of-custody audit files at `%APPDATA%\DFARS\audit\` plus rolling debug logs at `%LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log`

## Development

```
npm install
npm run tauri dev
```

Requires: Rust 1.80+, Node 20+, MSVC toolchain (VS 2022 Community or Build Tools with the "Desktop development with C++" workload, including the Windows 10/11 SDK).

## Build

```
cargo tauri build
```

Produces a per-user NSIS installer at `src-tauri/target/release/bundle/nsis/DFARS Desktop_2.0.0_x64-setup.exe`. Install target: `%LOCALAPPDATA%\Programs\DFARS Desktop\` — no admin prompt.

## Tests

```
# Rust (backend): 237 tests
cd src-tauri && cargo test

# Vitest (frontend): 443 tests
npm test
```

The `cargo test -- --ignored` gate runs two Windows Credential Manager integration tests that must pass on the release machine before shipping.

## Updates

v2.0.0 does not automatically check for updates. The updater plugin is wired but inert — the endpoint is a placeholder. To update to a newer version:

1. Download the latest `.msi` installer from the GitHub Releases page
2. Run it. Install is per-user; your data at `%APPDATA%\DFARS\` is preserved

Automatic updates will return in a post-v2.0.0 release once a signed update hosting location is configured.

### SmartScreen warning on first install

The installer is unsigned. Windows SmartScreen will display "Windows protected your PC" on first launch — click "More info" → "Run anyway". Authenticode certificates cost $100–400/year and this is a personal forensics tool. Subsequent launches are not affected.

## Data locations

| Data | Path |
|---|---|
| Forensics database | `%APPDATA%\DFARS\forensics.db` |
| Auth database | `%APPDATA%\DFARS\auth.db` |
| Config | `%APPDATA%\DFARS\config.json` |
| Evidence files | `<case.evidence_drive_path>\DFARS_Evidence\` or `%APPDATA%\DFARS\evidence_files\` (fallback) |
| Rolling debug logs | `%LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log` |
| Chain-of-custody audit | `%APPDATA%\DFARS\audit\*.txt` |
| Encryption key | Windows Credential Manager: `DFARS Desktop` / `totp_encryption_key` |

## Rollback

If an update breaks the app:

1. Download the previous version's `.msi` from GitHub Releases
2. Run it — reinstalling an earlier version does not touch `%APPDATA%\DFARS\`
3. Never delete old release assets — they are the rollback safety net

The `v1-final` git tag preserves the final v1 Python/Flask implementation for deep-forensic-reference purposes.

## Repository structure

```
dfars-desktop/
├── README.md                  — this file
├── docs/                      — architecture spec + security review history
│   ├── v2-migration-spec.md
│   ├── v2-project-plan.md
│   ├── sec-1-auth-architecture-review.md
│   ├── sec-3-file-upload-review.md
│   ├── sec-4-5-network-review.md
│   ├── sec-8-packaging-review.md
│   └── sec-9-final-release-review.md
├── src/                       — React 19 frontend (TanStack Router + Query, Shadcn/UI, Tailwind v4)
├── src-tauri/                 — Rust backend (Tauri 2, sqlx, axum, reqwest, argon2, totp-rs, lettre)
├── scratch/fernet_compat/     — Iteration 0 synthetic test vectors proving Python↔Rust Fernet interop
├── public/                    — static assets
├── package.json               — npm scripts
├── vite.config.ts             — Vite 7 with TanStack Router + Tailwind v4 plugins
└── vitest.config.ts           — Vitest config
```

## License

Private repository. All rights reserved.
