# PyInstaller spec for DFARS Desktop
# Build with: python packaging/build.py
# (or directly: pyinstaller packaging/dfars-desktop.spec --noconfirm)
#
# Output: dist/DFARS Desktop/  (--onedir layout)
#   - DFARS Desktop.exe        (the launcher)
#   - _internal/               (Python runtime + bundled data)
#       - app/templates/
#       - app/static/
#       - app/schema/
#       - <Python DLLs and dependencies>

# This spec is loaded by PyInstaller — globals like `Analysis`, `PYZ`,
# `EXE`, `COLLECT`, `block_cipher` are injected by the spec runner. It is
# NOT executed as a standalone Python module, so the linter complaints
# about undefined names below are expected.

import os
import sys
from pathlib import Path

# When pyinstaller invokes this spec, the working directory is the project
# root (where the spec file lives is in packaging/).
PROJECT_ROOT = Path(os.getcwd()).resolve()
APP_DIR = PROJECT_ROOT / "app"
ICON = str(APP_DIR / "static" / "dfars.ico")
VERSION_INFO = str(PROJECT_ROOT / "packaging" / "version_info.txt")


# ─── Bundled data files ────────────────────────────────────
#
# PyInstaller doesn't auto-include non-Python files. Each tuple is
# (source_path_relative_to_cwd, destination_path_inside_bundle).
# Destinations match the source layout so app/paths.py's
# Path(__file__).parent / "templates" still resolves correctly when frozen.
datas = [
    (str(APP_DIR / "templates"), "app/templates"),
    (str(APP_DIR / "static"), "app/static"),
    (str(APP_DIR / "schema"), "app/schema"),
]


# ─── Hidden imports ───────────────────────────────────────
#
# Modules PyInstaller's static analyzer misses, usually because they're
# imported dynamically by the libraries we use.
hiddenimports = [
    # PyWebView Windows backend (Edge WebView2)
    "webview.platforms.edgechromium",
    "webview.platforms.winforms",
    # CFFI backend used by argon2-cffi and cryptography
    "_cffi_backend",
    # argon2 internals — sometimes missed depending on the version
    "argon2.low_level",
    "argon2._utils",
    "argon2.exceptions",
    # Keyring Windows backend (Credential Manager via DPAPI)
    "keyring.backends.Windows",
    "keyring.backends.fail",
    "keyring.backends.null",
    "win32cred",
    "win32timezone",
    # Werkzeug bits sometimes missed by analyzer
    "werkzeug.routing.exceptions",
    "werkzeug.routing.rules",
    # PIL backends used by qrcode
    "PIL._tkinter_finder",
    # Email/MIME — Flask sometimes pulls these dynamically
    "email.mime.multipart",
    "email.mime.text",
    "email.mime.image",
]


# ─── Excludes ─────────────────────────────────────────────
#
# Modules PyInstaller would otherwise include but we don't need.
# Each one shaves megabytes off the build.
excludes = [
    "tkinter",       # we use pywebview, not tk
    "matplotlib",    # not used
    "scipy",         # not used
    "numpy",         # may be pulled in by PIL but we don't need it
    "pandas",
    "IPython",
    "jupyter",
    "notebook",
    "pytest",
    "test",
    "tests",
    "unittest",
    "litellm",       # we use Agent Zero for AI, not litellm directly
]


a = Analysis(
    [str(PROJECT_ROOT / "main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DFARS Desktop",
    icon=ICON,
    version=VERSION_INFO,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,           # windowed app, no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="DFARS Desktop",
)
