"""
Direction B, Step 2: Rust encrypt → Python decrypt
Reads sample2.json (written by Rust), decrypts with Python Fernet, verifies plaintext.
"""
import json
import sys
from cryptography.fernet import Fernet

EXPECTED_PLAINTEXT = b"dfars-test-plaintext-20260412"

input_path = "sample2.json"
try:
    with open(input_path, "r") as fp:
        data = json.load(fp)
except FileNotFoundError:
    print(f"[Python decrypt.py] ERROR: {input_path} not found — run 'cargo run -- encrypt' first")
    sys.exit(1)

key = data["key"].encode("utf-8")
ciphertext = data["ciphertext"].encode("utf-8")

print(f"[Python decrypt.py] Key:        {data['key']}")
print(f"[Python decrypt.py] Ciphertext: {data['ciphertext']}")

f = Fernet(key)
try:
    plaintext = f.decrypt(ciphertext)
except Exception as e:
    print(f"[Python decrypt.py] DECRYPTION FAILED: {e}")
    sys.exit(1)

print(f"[Python decrypt.py] Decrypted:  {plaintext}")

if plaintext == EXPECTED_PLAINTEXT:
    print("[Python decrypt.py] MATCH: plaintext matches expected byte-for-byte")
    print("[Python decrypt.py] Direction B PASS")
    sys.exit(0)
else:
    print(f"[Python decrypt.py] MISMATCH: got {plaintext!r}, expected {EXPECTED_PLAINTEXT!r}")
    print("[Python decrypt.py] Direction B FAIL")
    sys.exit(1)
