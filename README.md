# DFARS Desktop

**Digital Forensics Automated Reporting System** — SWGDE/NIST-aligned forensic
case management as a self-contained Windows desktop application.

A standalone successor to the Agent Zero-hosted DFARS Flask app. No Docker,
no browser, no container dependencies — just a native window, a local SQLite
database, and (optionally) Agent Zero on the side for AI-assisted features.

## Project status

| Phase | Feature                                                              | Status      |
|-------|----------------------------------------------------------------------|-------------|
| 1     | PyWebView desktop shell wrapping the DFARS Flask UI                  | done        |
| 2     | User authentication (Argon2id) + session management                  | done        |
| 3     | TOTP MFA with QR enrollment + recovery codes (Fernet-encrypted)      | done        |
| 4     | Agent Zero integration (REST API, plugin, AI-assisted UI helpers)    | done        |
| 5     | PyInstaller packaging + Inno Setup installer                         | done        |
| 6     | Auto-updates (Ed25519-signed manifests)                              | done        |

## Running in dev mode

```powershell
# From the project root
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

A native window opens. First launch creates `%APPDATA%\DFARS\`:

```
%APPDATA%\DFARS\
├── forensics.db    # SQLite case database
├── auth.db         # users + recovery codes + API tokens
├── config.json     # session secret, port config, Agent Zero settings
├── reports\        # generated reports
└── logs\           # application logs
```

The TOTP encryption key lives in **Windows Credential Manager** (Control Panel → User Accounts → Credential Manager → "DFARS Desktop"), tied to your Windows user account. Backups of `auth.db` alone are useless without the credential.

## Building a standalone .exe (Phase 5)

The desktop app can be packaged into a single distributable folder containing
the Python runtime, all dependencies, and the bundled assets.

### Prerequisites

- Python 3.10+ on Windows (WSL/Linux/macOS builds are not yet supported)
- The dev requirements: `pip install -r requirements-dev.txt`
- (Optional) Inno Setup 6.x from https://jrsoftware.org/isdl.php — only needed if you want to wrap the build into a Windows installer

### Build

```powershell
python packaging\build.py
```

This script:

1. Wipes `build/` and `dist/`
2. Runs PyInstaller against `packaging/dfars-desktop.spec` (onedir mode)
3. Reports the resulting binary path and size

Output:

```
dist/
└── DFARS Desktop/
    ├── DFARS Desktop.exe        ← double-click to launch
    └── _internal/               ← Python runtime + bundled templates/static/schema
```

You can copy the entire `dist/DFARS Desktop/` folder to any Windows machine
and run `DFARS Desktop.exe` directly — no Python installation required.

### Wrap as a Windows installer

```powershell
iscc packaging\installer.iss
```

This produces `dist/installer/DFARS-Desktop-Setup-1.0.0.exe`, a single
self-contained installer with:

- Start Menu shortcut
- Optional Desktop shortcut
- Registered uninstaller in Apps & Features
- Install location: `C:\Program Files\DFARS Desktop\`
- User data **preserved** in `%APPDATA%\DFARS\` on uninstall (delete it manually if you want a clean wipe)

### Caveats

- **Code signing**: the `.exe` is unsigned. Windows SmartScreen will warn first-time downloaders. To eliminate that warning, you need an Authenticode certificate (~$100-400/yr from Sectigo, DigiCert, etc.) and to sign both `DFARS Desktop.exe` and the installer with `signtool`. The build script does not do this.
- **WebView2 runtime**: PyWebView uses Microsoft Edge WebView2 for rendering. It's pre-installed on Windows 10/11 by default. If you target older systems, bundle the Evergreen Bootstrapper (~190KB) from Microsoft and install it before launching DFARS.
- **First-launch performance**: PyInstaller `--onedir` extracts nothing on launch (unlike `--onefile`), so cold start is fast — typically under 2 seconds.

## Auto-updates (Phase 6)

DFARS Desktop ships with an Ed25519-based update system. Updates are signed
with a private key you control and verified against an embedded public key,
so a compromised update server **cannot** push a malicious update to your
users — they'd need the private key, which lives offline on your build
machine.

### One-time setup (BEFORE you cut the first release)

```powershell
# 1. Generate your release-signing keypair
python packaging\keygen.py
```

This creates `packaging/release_private_key.pem` (gitignored — keep it
safe; treat it like a code-signing cert) and prints the matching public
key.

```powershell
# 2. Open app/update_key.py and replace _PLACEHOLDER_PUBLIC_KEY_PEM
#    with the public key the script just printed. Then re-build:
python packaging\build.py
```

Until this step is done, the embedded public key is the placeholder and
the updater **refuses** to install anything (it would otherwise validate
against a publicly-known key).

### Cutting a release

```powershell
# 1. Bump the version in two places
#    app/__init__.py             __version__ = "1.0.1"
#    packaging/version_info.txt  filevers + ProductVersion + FileVersion

# 2. Build the .exe and the installer
python packaging\build.py
iscc packaging\installer.iss

# 3. Sign the manifest
python packaging\sign_release.py `
    --installer dist\installer\DFARS-Desktop-Setup-1.0.1.exe `
    --version 1.0.1 `
    --download-url https://example.com/dfars-desktop/releases/DFARS-Desktop-Setup-1.0.1.exe `
    --notes "Bug fixes and minor improvements." `
    --output dist\installer\manifest.json

# 4. Upload to your update host
#    Upload BOTH the installer .exe AND manifest.json. The installer goes
#    to the URL you passed as --download-url; manifest.json goes to the
#    URL users have configured as `update_url` in config.json (the same
#    one across all installs).
```

That's it. Existing installs that have your `update_url` configured will
fetch the new manifest on their next "Check for Updates" click, verify
the signature against your embedded public key, download the installer,
verify its sha256, and launch it on user confirmation.

### Initial update_url configuration

Each install needs to know where to fetch the manifest from. Either:

- **Edit `%APPDATA%\DFARS\config.json`** and set
  `"update_url": "https://example.com/dfars-desktop/manifest.json"`, or
- **Bake it into the build** by editing the `DEFAULT_UPDATE_URL` constant
  in `app/updater.py` before running `build.py` so every fresh install
  knows where to look without manual config.

### What users see

In **Security → Updates**, the user sees their current version and a
"Check for Updates" button. After clicking, if a newer manifest exists,
they get an "Update available: 1.0.1" banner with release notes and an
"Install Update" button. Clicking it downloads the installer (with
signature + sha256 verification), launches it, and exits DFARS Desktop
so the installer can replace the running files. Inno Setup handles UAC,
file locking, and re-launching the new version.

## Project layout

```
dfars-desktop/
├── main.py                          PyWebView entry point + frozen-mode handling
├── requirements.txt                 runtime deps (bundled into .exe)
├── requirements-dev.txt             build/dev deps (PyInstaller etc.)
├── README.md
├── .gitignore
├── app/
│   ├── __init__.py
│   ├── paths.py                     %APPDATA%\DFARS\ discovery
│   ├── config.py                    config.json with atomic writes
│   ├── crypto.py                    Fernet key via keyring + file fallback
│   ├── auth.py                      Argon2id + TOTP + recovery codes
│   ├── auth_routes.py               /auth/* blueprint
│   ├── api_tokens.py                Bearer token CRUD for /api/v1
│   ├── api_routes.py                /api/v1/* REST API (Agent Zero pushes here)
│   ├── agent_zero_client.py         DFARS -> Agent Zero plugin client
│   ├── routes.py                    DFARS UI routes + /api/internal/ai/*
│   ├── flask_app.py                 Flask app factory + before_request auth gate
│   ├── database.py                  SQLite CRUD
│   ├── models.py                    Dataclasses
│   ├── report_generator.py          Sandboxed Jinja2 report rendering
│   ├── schema/
│   │   ├── database_schema.sql      forensics.db schema
│   │   └── auth_schema.sql          auth.db schema
│   ├── templates/                   Jinja2 templates
│   └── static/                      icons + assets
├── packaging/
│   ├── dfars-desktop.spec           PyInstaller spec (onedir)
│   ├── version_info.txt             Windows version metadata
│   ├── build.py                     run PyInstaller
│   └── installer.iss                Inno Setup installer script
└── docs/
    ├── phase2_smoke_test.py         auth flow tests
    ├── phase3_smoke_test.py         MFA flow tests
    ├── phase4_smoke_test.py         REST API + token flow tests
    └── phase4_integration_test.py   Agent Zero <-> DFARS round trip
```

## License

TBD
