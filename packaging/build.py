"""
DFARS Desktop build script.

Cleans previous build artifacts, runs PyInstaller against the spec file,
and reports where the output landed. Run from the project root:

    python packaging/build.py

Output:
    dist/DFARS Desktop/DFARS Desktop.exe   (the launcher)
    dist/DFARS Desktop/_internal/...       (Python runtime + bundled assets)

Once this completes, you can either:
    1. Distribute the dist/DFARS Desktop/ folder as a portable bundle, or
    2. Compile packaging/installer.iss with Inno Setup to produce an installer
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPEC_FILE = PROJECT_ROOT / "packaging" / "dfars-desktop.spec"
BUILD_DIR = PROJECT_ROOT / "build"
DIST_DIR = PROJECT_ROOT / "dist"
OUTPUT_DIR = DIST_DIR / "DFARS Desktop"
OUTPUT_EXE = OUTPUT_DIR / "DFARS Desktop.exe"


def banner(msg: str) -> None:
    print()
    print("=" * 70)
    print(f" {msg}")
    print("=" * 70)


def clean() -> None:
    banner("Cleaning previous build")
    for path in (BUILD_DIR, DIST_DIR):
        if path.exists():
            print(f"  removing {path}")
            shutil.rmtree(path, ignore_errors=True)
    print("  done")


def run_pyinstaller() -> int:
    banner("Running PyInstaller")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--log-level=WARN",
        str(SPEC_FILE),
    ]
    print(f"  $ {' '.join(cmd)}")
    print(f"  cwd = {PROJECT_ROOT}")
    print()
    return subprocess.call(cmd, cwd=str(PROJECT_ROOT))


def report() -> int:
    banner("Build result")
    if not OUTPUT_EXE.exists():
        print(f"  FAIL — expected output not found: {OUTPUT_EXE}")
        return 1

    exe_size_mb = OUTPUT_EXE.stat().st_size / (1024 * 1024)
    total_size = sum(
        f.stat().st_size for f in OUTPUT_DIR.rglob("*") if f.is_file()
    )
    total_size_mb = total_size / (1024 * 1024)

    print(f"  launcher : {OUTPUT_EXE}")
    print(f"             {exe_size_mb:6.1f} MB")
    print(f"  bundle   : {OUTPUT_DIR}")
    print(f"             {total_size_mb:6.1f} MB total")
    print()
    print("  Next steps:")
    print(f"    Test:    \"{OUTPUT_EXE}\"")
    print(f"    Install: compile packaging/installer.iss with Inno Setup")
    return 0


def main() -> int:
    if not SPEC_FILE.exists():
        print(f"FAIL — spec file not found: {SPEC_FILE}", file=sys.stderr)
        return 1

    clean()
    code = run_pyinstaller()
    if code != 0:
        print(f"\nFAIL — PyInstaller exited with status {code}", file=sys.stderr)
        return code

    return report()


if __name__ == "__main__":
    raise SystemExit(main())
