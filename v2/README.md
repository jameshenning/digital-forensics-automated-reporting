# DFARS Desktop v2

Tauri 2 + Rust + React 19 rebuild of DFARS Desktop. See `docs/v2-migration-spec.md` for the full architecture spec.

## Development

```
cd v2
npm install
npm run tauri dev
```

Requires: Rust 1.80+, Node 20+, MSVC toolchain (VS 2022 Community with C++ Desktop workload + Windows SDK 10).

## Build

```
npm run tauri build
```

Produces a signed `.msi` installer at `src-tauri/target/release/bundle/msi/`.

## Updates

DFARS Desktop v2.0.0 does not automatically check for updates. To
update to a newer version:

1. Download the latest `.msi` installer from the GitHub Releases
   page: https://github.com/jameshenning/digital-forensics-automated-reporting/releases
2. Run the installer. It installs per-user at
   `%LOCALAPPDATA%\Programs\DFARS Desktop\` — no admin required.
3. Your case data at `%APPDATA%\DFARS\` is preserved across reinstalls.

If an update breaks the app:

1. Open the GitHub Releases page
2. Download the previous version's `.msi`
3. Run it — this reinstalls the older version without affecting
   `%APPDATA%\DFARS\` data

Never delete old release assets — they are your rollback safety net.

A future version will enable in-app auto-updates once a signed update
hosting location is decided. Until then, manual updates via GitHub
Releases are the only path.

## SmartScreen warning on first install

**First install will trigger a SmartScreen warning.** Click "More info" then "Run anyway".
The installer is legitimate; it is unsigned because Authenticode certificates cost
$100-400/year and this is a personal forensics tool. Subsequent launches are not affected.

## Data locations

| Data | Path |
|---|---|
| Forensics database | `%APPDATA%\DFARS\forensics.db` |
| Auth database | `%APPDATA%\DFARS\auth.db` |
| Config | `%APPDATA%\DFARS\config.json` |
| Evidence files | `%APPDATA%\DFARS\evidence_files\` (or a configured external drive path) |
| Logs | `%LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log` |
| Encryption key | Windows Credential Manager: `DFARS Desktop` / `totp_encryption_key` |
