# SEC-8: Packaging + Auto-Updater Architecture Review
**DFARS Desktop v2 — Pre-Implementation Security Gate**
**Reviewer:** security-compliance-auditor
**Date:** 2026-04-12
**Status:** APPROVED WITH CONDITIONS
**Phase 6 implementation:** BLOCKED pending resolution of MUST-DO items 1, 2, and 3. All other Phase 6 work (audit log wiring, tauri.conf.json configuration, `.msi` test builds) may proceed in parallel.

---

## 1. Executive Summary

The v1 packaging and update system is well-designed for this threat model: Ed25519 signing with the private key kept off-disk from git, manifest canonicalization before signing, SHA-256 verification of the downloaded binary before launch, and a version-comparison guard that prevents acting on a stale manifest. Tauri's updater plugin uses the same signing algorithm and a compatible manifest format — the migration to `tauri-plugin-updater` is architecturally sound.

Three concerns must be resolved before Phase 6 code is written. First, the v1 private key (`packaging/release_private_key.pem`) exists on disk unencrypted, with `BUILTIN\Administrators Allow FullControl` in its ACL — anyone in the local Administrators group can read it without the owner knowing. The key must be moved to a dedicated directory outside the repo with ACL inheritance broken and access restricted to the owner account only. Second, `tauri.conf.json` currently has `"bundle.targets": "all"` with no `updater` section and no installer target narrowed to `msi` — Phase 6 must add the updater configuration, and must explicitly set `"createUpdaterArtifacts": true` together with the public key embedded in config before any updater-aware build ships. Third, the v1 private key has no passphrase (`-----BEGIN PRIVATE KEY-----`, not `-----BEGIN ENCRYPTED PRIVATE KEY-----`) — at rest protection is filesystem ACL only. This is acceptable for a personal tool but must be documented explicitly as an accepted risk rather than an oversight.

Two additional concerns are medium-severity. The spec §11 claim that "Ed25519 keys are reused from v1 — `packaging/keygen.py` output... already produced the public key that Tauri's updater expects (both use `ed25519-dalek`-compatible signatures)" requires a key format translation step that is not mentioned: Tauri's updater embeds the public key as a raw Base64 string (not a PEM block) in `tauri.conf.json`. The v1 `update_key.py` PEM cannot be pasted directly. Additionally, spec §10 still contains a stale keyring name (`service="dfars_desktop", account="fernet_key"`) that was already corrected in §7 by SEC-1 — this stale copy must be removed to prevent future confusion.

**Verdict: APPROVED WITH CONDITIONS.** Phase 6 may begin once MUST-DO items 1–3 are resolved. The core design (Ed25519 + manifest + SHA-256) is correct and the Tauri migration is low-risk. No fundamental re-architecture is required.

---

## 2. Findings by Area

### 2.1 Ed25519 Private Key — Existence, Location, and Protection

**What was found:**

`packaging/release_private_key.pem` exists on disk at `C:\Users\jhenn\dfars-desktop\packaging\release_private_key.pem`. File size is 119 bytes — consistent with a raw PKCS8 Ed25519 private key. The file header is `-----BEGIN PRIVATE KEY-----` (unencrypted PKCS8, no passphrase). The ACL is:

```
NT AUTHORITY\SYSTEM Allow  FullControl
BUILTIN\Administrators Allow  FullControl
CELL_HENNING\jhenn Allow  FullControl
```

The SDDL shows inherited permissions (`ID` flag), meaning the key inherits the repo directory's default ACL rather than having its own restricted ACL.

**Git history:** `git log --all -- "packaging/*.pem"` and `git log --all -- "packaging/release_private_key.pem"` both return empty. The key has never been committed. The `.gitignore` correctly excludes `packaging/release_private_key.pem` and `packaging/*.pem`. This is the most important protection and it is in place.

**Risks:**

1. The key is inside the repo directory tree. Any future `git add .` or `git add packaging/` from a different terminal (or a mis-configured IDE auto-stage) runs a non-trivial risk of committing it. The `.gitignore` protection relies on the gitignore rule being respected by every tool that touches the repo — a VS Code `git stash` + `git stash pop` workflow, for example, could surface the file in staging if the tool reads the stash list differently than gitignore.

2. `BUILTIN\Administrators Allow FullControl` is the standard inherited permission on Windows user-owned directories. For most files this is irrelevant, but an Ed25519 signing key is a crown jewel — anyone with admin rights on this machine (another account, a process running as SYSTEM) can read the key silently. The user is the only user on this machine (forensics workstation), so the practical risk is low, but the protection degrades to zero if an admin-level process (malware, a compromised tool running as SYSTEM, or a future second OS user) reads the file.

3. No passphrase protection means the key is immediately usable by any reader. If a backup tool copies it to OneDrive, or the disk is imaged, the key is immediately usable from the copy.

**Verdict:** The gitignore protection is correct and the key has never leaked to git. The ACL is the inherited default — not actively bad, but not hardened for a signing key. Remediation is a 2-minute `icacls` operation. See MUST-DO 1.

---

### 2.2 Key Reuse (v1 → v2) vs. Rotation — Decision and Implications

**Background:**

Reusing the existing key means every v1 install can receive an auto-update to v2 via Tauri's updater without any user action. Rotating means every v1 user must manually download and install v2, since their embedded public key would not verify a v2-signed manifest.

For this project — single user, the developer and the user are the same person — this decision has no multi-user coordination complexity. The relevant constraint is: **if the key rotates, the upgrade path from v1 to v2 requires a manual installer download.** Given that the user already understands this workflow, rotation is a viable option. However, there is no security reason to rotate: the key has never been committed, it is under the current user's control, and there is no known compromise event. Reuse is the correct call.

**Key format compatibility:**

The v1 key was generated by `keygen.py` using Python `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`. This produces a standard PKCS8 Ed25519 key. Tauri's updater (`tauri-plugin-updater`) uses the `minisign`-compatible key format for signing, not raw Ed25519 PKCS8.

This is the spec claim that requires the most scrutiny: §11 says "both use `ed25519-dalek`-compatible signatures." That is true at the cryptographic primitive level — the underlying Ed25519 algorithm is identical. However, Tauri's updater does NOT consume a PKCS8 PEM key or a raw Ed25519 public key directly. It uses the `minisign` key format:

- **Tauri private key format:** Generated by `tauri signer generate`, output is a minisign-format secret key file (not PKCS8 PEM). The private key bytes are the same Ed25519 scalar, but the file format is `minisign`'s own encoding (`RWRTY...` base64 blob).
- **Tauri public key in config:** Embedded in `tauri.conf.json` under `plugins.updater.pubkey` as a raw base64-encoded minisign public key string, NOT a PEM block.
- **Signing:** Done via `tauri signer sign --key <minisign-sk-file> <artifact>`, producing a `.sig` file in minisign format.

The v1 PKCS8 PEM key cannot be directly imported into Tauri's minisign-based signing workflow. The underlying Ed25519 key material (32-byte scalar) is the same format — it is theoretically possible to extract the raw bytes from the PKCS8 PEM and re-encode them into minisign's secret key format. However, this is a non-trivial operation (minisign adds its own header, key ID, and checksum around the raw key bytes), and doing it incorrectly produces a silently broken key.

**Practical recommendation:** Generate a new key pair using `tauri signer generate`. This produces the correct minisign-format key that Tauri's toolchain natively understands. Accept that v1 installs cannot auto-update to v2 via the updater — the user will do a fresh manual install of v2. Since there is exactly one user (the developer/owner), this is a non-issue. Do not attempt to port the v1 PKCS8 key into minisign format — the risk of subtle encoding errors silently breaking the signature verification chain is not worth it.

See MUST-DO 2.

---

### 2.3 Private Key Storage — Repo Location vs. Dedicated Directory

**Current state:** The key lives at `packaging/release_private_key.pem` inside the repo directory. Even with gitignore, this location creates exposure risk (see §2.1). The Tauri toolchain's convention is that the release signing key lives in the developer's home directory, entirely outside any version-controlled tree.

**Recommendation:** The new minisign-format private key (see §2.2) should be stored at `%USERPROFILE%\.dfars-release\` with a hardened ACL. See MUST-DO 1 (which applies equally to the new key location). The old PKCS8 PEM at `packaging/release_private_key.pem` becomes vestigial once v2 is shipped with a new key — delete it from the packaging directory at Phase 7 promotion.

---

### 2.4 `tauri.conf.json` — Missing Updater and Installer Configuration

**Current state:** `v2/src-tauri/tauri.conf.json` contains no `plugins.updater` section and no `bundle.windows` section. The bundle target is `"all"`, which produces every supported format (MSI, NSIS) rather than the intended MSI only.

**What Phase 6 must add:**

1. A `bundle.windows` section specifying `"wix"` (for MSI) or the appropriate WiX-based target.
2. A `plugins.updater` block containing:
   - `pubkey`: the minisign-format public key for the Tauri updater (base64 string, NOT PEM)
   - `endpoints`: the HTTPS URL(s) where `latest.json` is hosted
   - `dialog`: `true` (shows the user an update dialog rather than silent install)

3. `"createUpdaterArtifacts": true` under `bundle` (Tauri 2 flag that produces the `.sig` and `latest.json` alongside the installer artifact).

**Install scope (per-user vs. machine-wide):**

v1's Inno Setup script explicitly sets `PrivilegesRequired=admin` and `DefaultDirName={autopf}\{#MyAppName}` — meaning v1 installs to `C:\Program Files\DFARS Desktop\` and requires elevation. This is an **existing issue** that should not be replicated in v2. A single-user forensics tool has no reason to require administrative privileges for installation.

Tauri's WiX bundler supports per-user installs via the `wix.template` option or by setting `installerArgs` appropriately. When configured correctly, the installer targets `%LOCALAPPDATA%\Programs\DFARS Desktop\` (no admin prompt). This is the correct default for v2. See MUST-DO 3.

Note: the user data (`%APPDATA%\DFARS\`) is already a per-user path and is unaffected by the installer scope choice.

---

### 2.5 Updater Manifest Hosting

**Design:** Tauri's updater fetches a JSON manifest from one or more HTTPS URLs configured in `plugins.updater.endpoints`. The manifest (called `latest.json` by convention) contains the version, per-platform download URLs, and Ed25519 signatures over the artifact content.

**Recommended hosting layout:**

```
GitHub Releases (https://github.com/jameshenning/digital-forensics-automated-reporting/releases)
  └── Release: v2.0.1
        ├── DFARS-Desktop-Setup-2.0.1_x64.msi
        ├── DFARS-Desktop-Setup-2.0.1_x64.msi.sig   (minisign signature)
        └── latest.json                               (updater manifest)
```

The `endpoints` array in `tauri.conf.json` should point to the `latest.json` in the GitHub Releases `latest` redirect:

```
https://github.com/jameshenning/digital-forensics-automated-reporting/releases/latest/download/latest.json
```

GitHub Releases always serves over HTTPS (TLS 1.2+). There is no HTTP fallback at the GitHub layer. Tauri's updater will reject any endpoint that returns an HTTP redirect to plaintext HTTP (which GitHub never does). No additional TLS enforcement is needed beyond what Tauri provides by default.

**Manifest integrity chain:**

1. The `latest.json` is generated by `tauri build` when `"createUpdaterArtifacts": true` is set.
2. Each platform artifact entry contains a `signature` field: the minisign Ed25519 signature over the artifact bytes, signed with the developer's private key.
3. The updater plugin fetches `latest.json` over HTTPS, reads the version, compares to the running version, and if newer, downloads the MSI artifact.
4. Before installing, the plugin verifies the `signature` in the manifest against the embedded `pubkey` in the binary. A bad signature aborts the install with an error.
5. The SHA-256 of the artifact is implicit in the signature (the signature covers the artifact bytes directly, not a hash of the artifact separately). There is no separate SHA-256 field in Tauri's `latest.json` — the signature IS the integrity guarantee.

This chain is sound. The one gap is that `latest.json` itself is not separately signed as a document — its integrity is protected only by HTTPS transport. If GitHub's TLS were compromised (outside the threat model), an attacker could serve a modified `latest.json` pointing to a malicious artifact, but the artifact signature check would still fail unless the attacker also held the private key. The chain holds.

---

### 2.6 Downgrade / Replay Attack Guard

**v1 behavior:** `updater.py`'s `is_newer()` function explicitly checks `candidate > current` — a manifest for an older or equal version does not trigger an install. This prevents replay attacks where an attacker serves an old signed manifest.

**Tauri updater behavior:** `tauri-plugin-updater` performs the same check internally — it only offers the update if `manifest.version > current_version` (SemVer comparison). A signed manifest for an older version is fetched, verified, and then silently ignored because the version comparison fails. This is the correct behavior and matches v1.

**Verdict:** PASS. No additional downgrade guard needed at the application layer — the updater plugin implements it.

---

### 2.7 Authenticode Code-Signing Gap

**Status:** Both v1 and v2 ship unsigned binaries. Windows SmartScreen will display a "Windows protected your PC" screen on first download/run from a browser, requiring the user to click "More info" then "Run anyway." This is a UX friction point, not a security vulnerability — the file is what it claims to be; it just lacks a reputation signal.

**Practical impact for this project:** Single user. The developer is the user. The SmartScreen friction applies only to the first time the MSI is run on a machine. Subsequent auto-updates via Tauri's updater do not trigger SmartScreen (the MSI is launched by the already-running app, not downloaded from a browser).

**Cost of remediation:** An Authenticode OV (Organization Validation) code-signing certificate costs approximately $100–300 per year from a CA such as DigiCert, Sectigo, or GlobalSign. An EV (Extended Validation) certificate — which bypasses SmartScreen entirely without reputation building — costs approximately $300–500 per year and typically requires a hardware token (USB dongle) for the private key. Neither is required for Phase 6 or v2.0.0.

**Recommendation:** Document this as a known risk in the user-facing README. If the app is ever distributed beyond the single developer/user, revisit the OV cert. Not a blocker.

---

### 2.8 First-Run Migration from v1 to v2

**What happens on first v2 launch:**

1. v2 reads `%APPDATA%\DFARS\forensics.db` and `%APPDATA%\DFARS\auth.db` — same paths as v1.
2. `sqlx::migrate!()` runs the embedded migrations in order. Each migration is an `IF NOT EXISTS` DDL, so running against a v1 DB that already has all the tables results in no-ops.
3. The `sqlx` migrator records which migrations it has applied in the `_sqlx_migrations` table. On a v1 DB that has never seen sqlx, this table does not exist — `sqlx` creates it and marks all migrations as applied without re-running them, since the tables they create already exist.

**Edge case — the `_sqlx_migrations` checksum validation:**

sqlx's migrator validates the SHA-256 checksum of each migration file against what is recorded in `_sqlx_migrations`. On a DB that has never been touched by sqlx (i.e., the v1 DB), `_sqlx_migrations` is absent — sqlx inserts new rows for each migration. This is fine. If a user somehow has a partial `_sqlx_migrations` table from a development build of v2 (not a production concern but possible during development), sqlx will compare checksums and panic if the migration file changed. Ensure the migration files are locked before any development build touches a real production DB.

**Config.json compatibility:**

v2 reads `%APPDATA%\DFARS\config.json` with additive-only field semantics — unknown fields are ignored, missing new fields get defaults. This is safe.

**v1 detection and warning:**

v2 does not need to detect and warn about v1 — since both apps use the same data paths, there is no migration step. The user simply installs v2 and the data is there. The main caution is: do not run v1 and v2 simultaneously against the same SQLite files (write contention). This should be called out in the Phase 6 README note, not in-app (since detecting "v1 is also running" from within v2 is complex and adds no real protection — SQLite WAL mode handles concurrent reads safely and the single-user constraint means only one instance writes at a time).

**Verdict:** PASS. The sqlx migration design handles the v1-to-v2 handoff correctly. No data loss risk on first launch.

---

### 2.9 Auto-Update Rollback — Missing Mechanism

**Tauri updater behavior:** When the user accepts an update, Tauri downloads the new MSI and runs it with Windows Installer's standard upgrade logic. Windows Installer replaces the previous binary. There is no automatic rollback if the new binary fails to start.

**Risk:** If v2.0.1 ships with a bug that prevents the app from launching (a panic in `main()`, a missing DLL, a corrupt DB migration), the user's binary is now v2.0.1 and the v2.0.0 binary is gone. Recovery requires downloading the previous installer from GitHub Releases manually.

**Mitigation options:**

1. **Document the manual recovery path** in the README: "If an update renders the app unlaunchable, download the previous version's MSI from GitHub Releases and reinstall." This is the correct option for a personal tool. Low overhead.

2. **Keep the previous MSI on GitHub Releases** by never deleting old release assets (GitHub's default behavior — releases persist unless manually deleted). This is already true if releases are handled normally.

3. **`.exe.bak` strategy:** Before Tauri runs the new MSI, copy the current binary to `<install-dir>\DFARS Desktop.exe.bak`. The MSI replaces `DFARS Desktop.exe` but does not know about `.bak`. If the new version fails to launch, the user can rename `.bak` to `.exe` to restore. This is a SHOULD-DO, not a MUST-DO — it requires a custom WiX action or a pre-update hook that Tauri does not natively support.

**Recommendation:** Implement option 1 (document it) and ensure option 2 is preserved by policy (never delete GitHub Release assets). Option 3 is a SHOULD-DO for a future iteration.

---

### 2.10 Audit Log Configuration and Sensitive Field Leakage

**Current state:** `Cargo.toml` already includes `tracing = "0.1"`, `tracing-subscriber = "0.3"`, and `tracing-appender = "0.2"`. These dependencies are in place but the log configuration has not been wired into the Phase 6 implementation yet.

**What should be logged (appropriate):**

- App launch / shutdown with version string
- Authentication events: login success, login failure (username only, never password), lockout triggered, MFA success, MFA failure, recovery code used
- Session lifecycle: session created, session expired (inactivity), session terminated by logout
- API token events: created (name only), revoked
- Case mutations via API: created, updated (actor and case ID only)
- Evidence file upload: file ID, evidence ID, SHA-256 (not the path within the evidence drive beyond the top-level directory name)
- Evidence file hash verification failures: file ID, stored hash, computed hash — at ERROR severity
- Evidence file purge: file ID, purge justification, SHA-256 (for post-hoc CoC)
- Updater events: check performed, update found (version), update downloaded, update launched, signature verification failure
- axum startup: bind address, port (at WARN if bound to non-loopback)
- Agent Zero call audit: command name, fields sent (field names only, not values), timestamp
- Audit log entries from `share_record`

**What MUST NOT be logged:**

- Session tokens (plaintext `sess_...` strings)
- API tokens (plaintext `dfars_...` strings)
- Fernet key or any cryptographic key material
- Argon2 hashes or plaintext passwords
- Decrypted TOTP secrets
- Decrypted Agent Zero API key
- Decrypted SMTP password
- File contents (evidence file bytes)
- Full absolute paths to evidence files (log the `<case_id>/<evidence_id>/` segment only, not the full drive path which may reveal forensic drive labels)
- Case narrative text, analysis notes, evidence descriptions (these are the case's confidential content — the log is not a case record)
- `config.json` contents verbatim

**Rotation policy:**

`tracing-appender` supports rolling file appender with daily or per-megabyte rotation. Recommended configuration:

- Rolling by size: 10 MB maximum per log file
- Retain up to 5 rolled files (50 MB total log footprint)
- File prefix: `dfars-desktop.log`, rolled files named `dfars-desktop.log.1`, `.log.2`, etc.
- No compression required (log files at this size are not a storage concern)
- Single-file-per-launch (truncate on startup) is NOT recommended — the rolling approach preserves the last several sessions, which is useful for debugging and for correlating an audit event to a specific launch.

**Log file location:** `%LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log`. `%LOCALAPPDATA%` is per-user by definition on Windows — no additional ACL hardening is needed. The directory inherits `jhenn: FullControl` from `%LOCALAPPDATA%`; other user accounts cannot read it.

---

### 2.11 Data Preservation During Auto-Update

**What the Tauri/WiX MSI updater touches:**

The MSI installer replaces files under the install directory (`%LOCALAPPDATA%\Programs\DFARS Desktop\` for a per-user install). It does NOT touch:

- `%APPDATA%\DFARS\` (forensics.db, auth.db, config.json, evidence_files/)
- `%LOCALAPPDATA%\DFARS\Logs\` (log files)
- Credential Manager entries (keyring)

These paths are outside the MSI's install root and Windows Installer does not manage them. They survive upgrades, downgrades, and uninstalls unchanged. This is the correct behavior — `forensics.db` and `auth.db` must survive upgrades.

**Verification requirement:** The Phase 6 clean-machine install test (per the project plan) should also include an upgrade test: install v2.0.0, create a case, trigger the updater with a simulated v2.0.1 manifest, verify the case data survives. This is the only way to confirm the MSI upgrade path does not accidentally place data files inside the install root (which would put them at risk).

**Uninstall behavior:** v1's `installer.iss` explicitly documents that `%APPDATA%\DFARS\` is NOT deleted on uninstall (the `[UninstallDelete]` section is empty for data files). v2's WiX installer must preserve this behavior. The WiX template should never include `%APPDATA%\DFARS\` as a managed component. This is the default WiX behavior (only install-root components are managed), but it should be verified in the Phase 6 clean-machine uninstall test.

---

### 2.12 Spec §10 Stale Keyring Name — Live Defect

**Finding:** `docs/v2-migration-spec.md` §10 ("Data migration from existing v1 installs"), line reading:

> **Keyring entry**: `service="dfars_desktop", account="fernet_key"` → both apps read it.

This is the WRONG keyring name. SEC-1 corrected the spec in §7: the actual v1 keyring entry is `service="DFARS Desktop"` (with a space, capital D, capital F) and `account="totp_encryption_key"`. §10 was not updated when §7 was corrected.

If an implementer reads §10 as the authority on keyring names (a reasonable reading — §10 is the migration section and should be authoritative for v1 data), they will implement the wrong names and silently orphan all v1 encrypted data on first v2 launch. This is the same data-loss bug that SEC-1 flagged as its top finding.

**Remediation:** The stale text in §10 must be corrected before Phase 1 implementation begins (it is already too late for Phase 6 to be the first time this is noticed — but if it has not been corrected yet, correct it now). See MUST-DO 4. This is a spec defect, not a code defect, but it is operationally equivalent to a P0 bug.

---

### 2.13 Private Key Unencrypted at Rest

**Finding:** `keygen.py` uses `encryption_algorithm=serialization.NoEncryption()` when writing the private key PEM. The key is readable by any process that can open the file. There is no passphrase.

**Risk in this threat model:** Low. The machine is a single-user forensics workstation. The key's only capability is signing future update manifests — an attacker who reads it can push a malicious update that existing v1/v2 installs would accept. However, the attacker must also control the `endpoints` URL that the app checks for updates (GitHub Releases, served over HTTPS with certificate validation). A network-level MITM is outside this threat model. A local attacker who reads the key and also controls the update endpoint is an attacker who already owns the machine.

**Verdict:** Acceptable risk for this threat model. Document explicitly. If the key is ever rotated or a new minisign key is generated, use `tauri signer generate -p` to set a passphrase on the minisign secret key file — Tauri's toolchain supports this natively and the passphrase is only needed at signing time (build time), not embedded in anything.

---

## 3. MUST-DOs (Blocking Phase 6)

**MUST-DO 1 — Harden the private key ACL and move it out of the repo tree**

The new minisign-format signing key (generated per MUST-DO 2) must be stored at `%USERPROFILE%\.dfars-release\` outside of the repo directory. Apply a restricted ACL:

```
icacls %USERPROFILE%\.dfars-release /inheritance:r
icacls %USERPROFILE%\.dfars-release /grant:r "%USERNAME%:(OI)(CI)F"
```

The first command breaks ACL inheritance (removes the `BUILTIN\Administrators` and `NT AUTHORITY\SYSTEM` inherited entries). The second grants only the current user full control. Verify the result with:

```
icacls %USERPROFILE%\.dfars-release\tauri-signing-key.key
```

The output should show only `CELL_HENNING\jhenn:(F)` — no SYSTEM, no Administrators.

The old `packaging/release_private_key.pem` may remain where it is for now (it is gitignored and was never committed). Delete it at Phase 7 promotion when the `packaging/` directory is removed.

**MUST-DO 2 — Generate a new minisign-format key pair with `tauri signer generate`**

Do not attempt to convert v1's PKCS8 PEM into minisign format. Generate a fresh key pair:

```
cargo tauri signer generate -w %USERPROFILE%\.dfars-release\tauri-signing-key.key
```

This produces:
- `%USERPROFILE%\.dfars-release\tauri-signing-key.key` — the minisign secret key (keep private, apply MUST-DO 1 ACL)
- stdout output of the corresponding public key string (e.g., `dW50cnVzdGVkIGNvbW1lbnQ6...`) — this is what goes in `tauri.conf.json`

Record the public key string. Embed it in `tauri.conf.json` under `plugins.updater.pubkey`. Do NOT store the public key in a separate file at the repo root (it is not sensitive, but storing it in config is cleaner).

The consequence of generating a new key is that v1 installs cannot auto-update to v2 via the updater. Given the single-user context, this is acceptable — the user performs a manual install of v2.0.0 via the MSI and then all subsequent v2.x updates flow through the Tauri updater automatically.

**MUST-DO 3 — Configure per-user MSI install (no admin prompt)**

In `tauri.conf.json`, add a `bundle.windows` section specifying per-user install scope. Using Tauri 2's NSIS bundler is the simplest path to a per-user no-elevation installer; WiX/MSI per-user mode requires additional WiX fragment customization. Evaluate which bundler Tauri 2 defaults to for Windows and whether NSIS or WiX better fits the Phase 6 timeline.

Regardless of bundler choice, verify the install target is `%LOCALAPPDATA%\Programs\DFARS Desktop\` (not `%ProgramFiles%`). Run `tauri build`, install the output on a clean VM, and confirm no UAC elevation prompt appears. If the Tauri default installs to Program Files (admin-required), add `--installer-args /CURRENTUSER` (NSIS) or the WiX equivalent to the build command.

The v1 `installer.iss` setting `PrivilegesRequired=admin` and `DefaultDirName={autopf}` should not be replicated in v2.

**MUST-DO 4 — Correct the stale keyring name in spec §10**

In `docs/v2-migration-spec.md` §10, replace:

> **Keyring entry**: `service="dfars_desktop", account="fernet_key"` → both apps read it.

With:

> **Keyring entry**: `service="DFARS Desktop", account="totp_encryption_key"` — exact strings, case-sensitive, matching v1's `app/crypto.py`. See §7 and SEC-1 for details. Both apps read the same entry.

This is a spec defect that creates a data-loss risk if the Phase 1 implementer treats §10 as authoritative. It should have been fixed when SEC-1 corrected §7 — fix it now before Phase 6.

---

## 4. SHOULD-DOs (Non-Blocking)

**SHOULD-DO 1 — Add a passphrase to the minisign signing key**

When running `cargo tauri signer generate`, add the `-p` flag to prompt for a passphrase:

```
cargo tauri signer generate -w %USERPROFILE%\.dfars-release\tauri-signing-key.key -p
```

The passphrase is required only at signing time (during `tauri build`). It does not affect runtime behavior. It adds a second factor of protection if the key file is ever read by an unauthorized party (e.g., a backup tool copies it to OneDrive before the ACL restriction is applied). Low overhead, meaningful defense-in-depth.

**SHOULD-DO 2 — Add an updater section to `tauri.conf.json` before first build**

Phase 6's first deliverable should be a `tauri.conf.json` that includes the complete updater configuration:

```json
"plugins": {
  "updater": {
    "pubkey": "<minisign public key string from MUST-DO 2>",
    "endpoints": [
      "https://github.com/jameshenning/digital-forensics-automated-reporting/releases/latest/download/latest.json"
    ],
    "dialog": true
  }
}
```

Set this before any build that enables `"createUpdaterArtifacts": true`. Building with the artifact flag but without a configured pubkey causes a build-time error (which is safe — fail closed), but better to configure correctly from the start.

**SHOULD-DO 3 — Document manual rollback path in the README**

Add a section to the v2 README:

> **If an update breaks the app:** Download the previous version's MSI from the GitHub Releases page and reinstall. Your case data at `%APPDATA%\DFARS\` will not be affected by the reinstall. The previous release remains available on GitHub — never delete old release assets.

One paragraph. Low overhead. Eliminates the "how do I recover?" question.

**SHOULD-DO 4 — Audit log `tracing_appender` wiring in Phase 6**

Phase 6 is listed in the project plan as the iteration that wires `tracing-appender`. Before Phase 6 merges, confirm the following:

- The rolling appender is initialized in `main.rs` before any Tauri command can execute.
- The appender is configured with `NonBlocking` mode (Tauri's main thread must not block on log I/O).
- The log directory (`%LOCALAPPDATA%\DFARS\Logs\`) is created with `std::fs::create_dir_all` at startup if it does not exist — do not assume it exists.
- The `tracing::subscriber` is set as the global default before the first `tracing::info!()` call.

**SHOULD-DO 5 — Define the `latest.json` release workflow before Phase 6 ships**

The Tauri build with `"createUpdaterArtifacts": true` auto-generates `latest.json` and `.sig` files alongside the MSI. The Phase 6 release workflow should specify:

1. Run `cargo tauri build` (produces MSI + `.sig` + `latest.json`).
2. Create a GitHub Release with the version tag.
3. Upload the MSI and `latest.json` to the release assets.
4. Verify the `latest.json` endpoint URL matches the configured `endpoints` in `tauri.conf.json`.

This workflow replaces the v1 manual `python packaging/sign_release.py ...` step. Document it in the v2 README before Phase 6 closes.

**SHOULD-DO 6 — Upgrade test in Phase 6 QA checklist**

The project plan's Phase 6 stop-ship criterion lists "receives an auto-update notification when a signed manifest is served" but does not explicitly call out data survival. Add to the QA checklist:

- Install v2.0.0 MSI on clean VM
- Login, create a case with one evidence item
- Serve a simulated v2.0.1 manifest (signed with the same minisign key, pointing to a v2.0.1 build)
- Accept the update
- After restart: confirm the case and evidence item created in v2.0.0 still exist
- Confirm `auth.db` was not reset (login still works with existing credentials)

---

## 5. Open Questions (Require User Input Before Phase 6 Coding Starts)

**OQ-SEC8-1 — NSIS vs. WiX bundler choice**

Tauri 2 supports both NSIS and WiX/MSI bundlers for Windows. NSIS is simpler to configure for per-user installs (no admin prompt by default). WiX produces true `.msi` files with Windows Installer semantics (rollback on failure, better enterprise deploy tooling). For a single-user personal tool, NSIS is the pragmatic choice. For a tool that might eventually be deployed via Group Policy or SCCM, MSI is the right long-term choice.

**Decision needed:** NSIS (simpler, per-user by default, no admin) or WiX MSI (true Windows Installer, requires extra WiX fragment for per-user)?

Default if no response by Phase 6 start: **NSIS.** It is the Tauri 2 default on Windows and produces per-user installs without additional configuration.

**OQ-SEC8-2 — Update check trigger: manual only vs. on-launch check**

Should v2 automatically check for updates on every app launch, or should updates be user-initiated only (via a "Check for Updates" button in settings)?

- **On-launch check:** Calls the `endpoints` URL every time the app opens. Adds a network request on startup (15-second timeout, non-blocking). Ensures the user is always notified of updates promptly.
- **Manual only:** No automatic outbound connection on launch. Preserves the app's current "no network calls except when explicitly triggered" posture. Matches the forensic app's principle of no unexpected outbound traffic.

**Default if no response:** Manual only, surfaced as "Check for Updates" in the Settings → About screen. This is the more conservative choice and aligns with the forensic app's network posture. The `updater_check()` Tauri command is already in the spec; it just needs a UI trigger.

**OQ-SEC8-3 — GitHub repository name and release URL**

The recommended manifest endpoint:

```
https://github.com/jameshenning/digital-forensics-automated-reporting/releases/latest/download/latest.json
```

This URL is derived from the memory context but has not been verified against the actual GitHub repository name and visibility. Confirm the repository is public (GitHub Releases download URLs for private repos require authentication, which the Tauri updater cannot provide without an additional token). If the repo is private, an alternative hosting option (e.g., a public GitHub Gist or a Cloudflare Pages endpoint) is needed for the `latest.json`.

---

## 6. Sign-Off Conditions

Phase 6 implementation may proceed when:

1. MUST-DO 1 is verified: `icacls %USERPROFILE%\.dfars-release\tauri-signing-key.key` shows only `CELL_HENNING\jhenn:(F)`.
2. MUST-DO 2 is verified: `cargo tauri signer generate` has been run, the public key string is in `tauri.conf.json` under `plugins.updater.pubkey`, and a test build produces a `.sig` file alongside the MSI artifact.
3. MUST-DO 3 is verified: a test install on a clean machine (or VM) completes without a UAC elevation prompt and installs to `%LOCALAPPDATA%\Programs\` or equivalent per-user path.
4. MUST-DO 4 is verified: spec §10 has been corrected and the correction is committed.
5. OQ-SEC8-1 is answered: bundler choice (NSIS vs. WiX) is recorded in the spec.
6. OQ-SEC8-2 is answered: update check trigger is recorded in the spec.

SHOULD-DOs 1–6 are recommended before Phase 6 closes but are not blocking conditions for implementation start. They are blocking conditions for Phase 6 stop-ship (the updater must be functionally correct before the phase closes, and that requires SHOULD-DOs 4 and 5 to be in place).

---

## Compliance Notes

This application handles chain-of-custody data with legal significance. No GDPR/HIPAA/PCI-DSS regulated data flows through the packaging or update path — the updater downloads the application binary, not user data. The relevant concern is **integrity**: a tampered update that overwrites the forensics app binary would compromise the integrity of all future case records created with it. The Ed25519 + minisign signing chain addresses this directly.

For NIST 800-171 (CUI handling in forensic context): the update mechanism's signature verification and HTTPS delivery are appropriate controls for the software integrity protection requirement (3.13.10 — protection of CUI in storage and transit applies to the app binary as the system that processes CUI).
