use std::fs;
use std::process;
use fernet::Fernet;
use serde::{Deserialize, Serialize};

const PLAINTEXT: &[u8] = b"dfars-test-plaintext-20260412";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Serialize, Deserialize)]
struct Sample {
    key: String,
    ciphertext: String,
    plaintext_hex: String,
}

/// Direction A: Read sample.json (Python-produced), decrypt with Rust fernet, verify.
fn direction_a_decrypt() {
    println!("[Rust decrypt] Reading sample.json (Python-encrypted) ...");

    let raw = fs::read_to_string("sample.json").unwrap_or_else(|e| {
        eprintln!("[Rust decrypt] ERROR reading sample.json: {e}");
        eprintln!("[Rust decrypt] Run `python python/encrypt.py` from the fernet_compat directory first.");
        process::exit(1);
    });

    let sample: Sample = serde_json::from_str(&raw).unwrap_or_else(|e| {
        eprintln!("[Rust decrypt] ERROR parsing sample.json: {e}");
        process::exit(1);
    });

    println!("[Rust decrypt] Key:        {}", sample.key);
    println!("[Rust decrypt] Ciphertext: {}", sample.ciphertext);

    let fernet = Fernet::new(&sample.key).unwrap_or_else(|| {
        eprintln!("[Rust decrypt] ERROR: fernet::Fernet::new() returned None — key format rejected");
        process::exit(1);
    });

    match fernet.decrypt(&sample.ciphertext) {
        Ok(plaintext_bytes) => {
            println!("[Rust decrypt] Decrypted bytes: {:?}", plaintext_bytes);
            if plaintext_bytes == PLAINTEXT {
                println!("[Rust decrypt] MATCH: plaintext matches expected byte-for-byte");
                println!("[Rust decrypt] Direction A PASS");
            } else {
                eprintln!(
                    "[Rust decrypt] MISMATCH: got {:?}, expected {:?}",
                    plaintext_bytes, PLAINTEXT
                );
                eprintln!("[Rust decrypt] Direction A FAIL");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[Rust decrypt] DECRYPTION FAILED: {:?}", e);
            eprintln!("[Rust decrypt] Direction A FAIL");
            process::exit(1);
        }
    }
}

/// Direction B: Generate a Rust fernet key, encrypt known plaintext, write sample2.json.
fn direction_b_encrypt() {
    println!("[Rust encrypt] Generating new Fernet key via Rust fernet crate ...");

    let key = Fernet::generate_key();
    let fernet = Fernet::new(&key).unwrap_or_else(|| {
        eprintln!("[Rust encrypt] ERROR: fernet::Fernet::new() returned None on freshly generated key");
        process::exit(1);
    });

    let ciphertext = fernet.encrypt(PLAINTEXT);

    println!("[Rust encrypt] Key:        {}", key);
    println!("[Rust encrypt] Ciphertext: {}", ciphertext);

    let sample = Sample {
        key: key.clone(),
        ciphertext: ciphertext.clone(),
        plaintext_hex: to_hex(PLAINTEXT),
    };

    let json = serde_json::to_string_pretty(&sample).unwrap();
    fs::write("sample2.json", &json).unwrap_or_else(|e| {
        eprintln!("[Rust encrypt] ERROR writing sample2.json: {e}");
        process::exit(1);
    });

    println!("[Rust encrypt] Written to: sample2.json");
    println!("[Rust encrypt] DONE — now run: python python/decrypt.py");
}

fn usage() {
    eprintln!("Usage: fernet-compat <decrypt|encrypt>");
    eprintln!("  decrypt  -- Direction A: read sample.json (Python-produced), verify Rust can decrypt");
    eprintln!("  encrypt  -- Direction B: Rust generates key+ciphertext, writes sample2.json for Python");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("decrypt") => direction_a_decrypt(),
        Some("encrypt") => direction_b_encrypt(),
        _ => usage(),
    }
}
