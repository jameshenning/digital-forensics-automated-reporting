"""
Direction A, Step 1-2: Python encrypt → Rust decrypt
Generates a fresh Fernet key, encrypts known plaintext, writes sample.json.
"""
import json
from cryptography.fernet import Fernet

PLAINTEXT = b"dfars-test-plaintext-20260412"

key = Fernet.generate_key()
f = Fernet(key)
ciphertext = f.encrypt(PLAINTEXT)

output = {
    "key": key.decode("utf-8"),
    "ciphertext": ciphertext.decode("utf-8"),
    "plaintext_hex": PLAINTEXT.hex(),
}

output_path = "sample.json"
with open(output_path, "w") as fp:
    json.dump(output, fp, indent=2)

print(f"[Python encrypt.py] Key:        {key.decode()}")
print(f"[Python encrypt.py] Ciphertext: {ciphertext.decode()}")
print(f"[Python encrypt.py] Written to: {output_path}")
print(f"[Python encrypt.py] DONE")
