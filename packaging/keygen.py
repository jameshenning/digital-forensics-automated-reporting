"""
DFARS Desktop release-signing keypair generator.

Run this ONCE during initial project setup. It produces:

  packaging/release_private_key.pem    KEEP THIS PRIVATE — gitignored

It also prints the matching public key to stdout. You then paste that
PEM into app/update_key.py and rebuild the .exe.

Why is this here:
  - Updates are verified against an Ed25519 public key embedded in the
    .exe at build time.
  - The matching private key signs every release manifest before upload.
  - Anyone with the private key can push updates that the embedded
    public key will accept — that's why it must NEVER end up in git.

Run with:
    python packaging/keygen.py

Refuses to overwrite an existing private key (delete it manually first
if you really mean to rotate).
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = PROJECT_ROOT / "packaging" / "release_private_key.pem"


def main() -> int:
    if PRIVATE_KEY_PATH.exists():
        print(f"FAIL — private key already exists at {PRIVATE_KEY_PATH}", file=sys.stderr)
        print("       Delete it manually if you really want to rotate. This will", file=sys.stderr)
        print("       break update verification for every existing install until", file=sys.stderr)
        print("       you ship a new build with the new public key embedded.", file=sys.stderr)
        return 1

    print("Generating Ed25519 keypair...")
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(priv_pem)
    print()
    print(f"  private key written to: {PRIVATE_KEY_PATH}")
    print(f"  (this file is gitignored — never commit it)")
    print()
    print("Public key (paste this into app/update_key.py PUBLIC_KEY_PEM):")
    print()
    print(pub_pem.decode("ascii"))
    print()
    print("Next steps:")
    print("  1. Open app/update_key.py")
    print("  2. Replace _PLACEHOLDER_PUBLIC_KEY_PEM with the public key above")
    print("  3. Set PUBLIC_KEY_PEM = (the new value)")
    print("  4. Rebuild the .exe with: python packaging/build.py")
    print("  5. Sign every release with: python packaging/sign_release.py ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
