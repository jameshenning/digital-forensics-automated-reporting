"""
DFARS Desktop release manifest signer.

After you've built an installer with `iscc packaging/installer.iss`, run
this to produce the signed manifest.json that gets uploaded alongside it.

Usage:
    python packaging/sign_release.py \\
        --installer dist/installer/DFARS-Desktop-Setup-1.0.1.exe \\
        --version   1.0.1 \\
        --download-url https://example.com/dfars-desktop/releases/DFARS-Desktop-Setup-1.0.1.exe \\
        --notes     "Bug fixes and small improvements." \\
        --output    dist/installer/manifest.json

The script:
  1. Computes the sha256 of the installer .exe
  2. Builds a manifest dict with version + download URL + sha256 + size
  3. Signs the canonicalized manifest with the private key from
     packaging/release_private_key.pem (created by keygen.py)
  4. Writes the signed JSON to --output

Upload BOTH the installer and manifest.json to your update_url. The
installer at the URL referenced inside manifest.json's windows_x64.url.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Reuse the canonicalization function from the runtime module so signer
# and verifier produce identical bytes.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.updater import canonical_manifest_bytes  # noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = PROJECT_ROOT / "packaging" / "release_private_key.pem"


def load_private_key() -> Ed25519PrivateKey:
    if not PRIVATE_KEY_PATH.exists():
        raise SystemExit(
            f"Private key not found at {PRIVATE_KEY_PATH}.\n"
            f"Run `python packaging/keygen.py` first."
        )
    pem = PRIVATE_KEY_PATH.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(
            f"Key at {PRIVATE_KEY_PATH} is not Ed25519 (got {type(key).__name__})."
        )
    return key


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(
    version: str,
    installer: Path,
    download_url: str,
    notes: str,
    channel: str,
) -> dict:
    if not installer.exists():
        raise SystemExit(f"Installer file not found: {installer}")

    return {
        "version": version,
        "released_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "channel": channel,
        "notes": notes,
        "windows_x64": {
            "url": download_url,
            "sha256": sha256_file(installer),
            "size_bytes": installer.stat().st_size,
        },
    }


def sign_manifest(manifest: dict, key: Ed25519PrivateKey) -> dict:
    payload = canonical_manifest_bytes(manifest)
    signature = key.sign(payload)
    return {**manifest, "signature": base64.b64encode(signature).decode("ascii")}


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a DFARS Desktop release manifest.")
    parser.add_argument("--installer", required=True, type=Path,
                        help="Path to the Inno Setup installer .exe")
    parser.add_argument("--version", required=True,
                        help="Release version (e.g. 1.0.1)")
    parser.add_argument("--download-url", required=True,
                        help="Public HTTPS URL where the installer will be hosted")
    parser.add_argument("--notes", default="",
                        help="Release notes (one paragraph; users see this)")
    parser.add_argument("--channel", default="stable",
                        help="Release channel (default: stable)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Where to write manifest.json (default: stdout)")

    args = parser.parse_args()

    key = load_private_key()
    manifest = build_manifest(
        version=args.version,
        installer=args.installer,
        download_url=args.download_url,
        notes=args.notes,
        channel=args.channel,
    )
    signed = sign_manifest(manifest, key)

    out_text = json.dumps(signed, indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out_text, encoding="utf-8")
        print(f"Signed manifest written to {args.output}")
        print(f"  version: {args.version}")
        print(f"  sha256:  {signed['windows_x64']['sha256']}")
        print(f"  size:    {signed['windows_x64']['size_bytes']:,} bytes")
    else:
        sys.stdout.write(out_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
