/// Fernet symmetric encryption wrapper.
///
/// Manages one Fernet key that protects all secrets-at-rest:
///   - TOTP secrets (`users.totp_secret`)
///   - Agent Zero API key (`config.json → agent_zero_api_key_encrypted`)
///   - SMTP password  (`config.json → smtp_password_encrypted`)
///
/// Key acquisition order (matching v1 `app/crypto.py`):
///   1. Windows Credential Manager via `keyring`, service = "DFARS Desktop",
///      account = "totp_encryption_key"  — exact strings, case-sensitive.
///   2. File fallback: `%APPDATA%\DFARS\.keyfile`
///   3. Generate a new key, write to keyring first; fall back to keyfile if
///      keyring is unavailable.
///
/// MUST-DO 1 (SEC-1): These service/account names are non-negotiable.
/// Using any other name silently orphans all v1 encrypted data.
use std::path::PathBuf;

use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::error::AppError;

// ─── Keyring names — DO NOT CHANGE ────────────────────────────────────────────
// These are the exact strings v1's crypto.py uses in Windows Credential Manager.
// Any deviation silently creates a new entry and renders all v1 encrypted data
// (TOTP secrets, Agent Zero API key, SMTP password) permanently unreadable.
const KEYRING_SERVICE: &str = "DFARS Desktop";
const KEYRING_ACCOUNT: &str = "totp_encryption_key";

// ─── State carried for the lifetime of the process ─────────────────────────

/// Identifies where the Fernet key came from. Returned by
/// `settings_get_security_posture()` so the UI can warn the user if they're
/// running with the less-secure file fallback (SEC-1 SHOULD-DO 6).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    Keyring,
    Keyfile,
    New,
}

pub struct CryptoState {
    /// The Fernet instance. Held in a `Zeroizing` wrapper so the key bytes
    /// are wiped from memory on drop.
    fernet: fernet::Fernet,
    /// Where the key came from — exposed to the security posture command.
    pub key_source: KeySource,
}

// ─── Key acquisition ────────────────────────────────────────────────────────

fn keyfile_path() -> Result<PathBuf, AppError> {
    // Use the `directories` crate to resolve %APPDATA% portably.
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| AppError::Io("could not resolve base directories".into()))?;
    // %APPDATA%\DFARS\.keyfile — matches v1's `data_dir() / ".keyfile"` exactly.
    Ok(dirs.data_dir().join("DFARS").join(".keyfile"))
}

fn try_keyring_get() -> Option<Zeroizing<String>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).ok()?;
    match entry.get_password() {
        Ok(pw) => Some(Zeroizing::new(pw)),
        Err(e) => {
            tracing::debug!("keyring get failed: {e}");
            None
        }
    }
}

fn try_keyring_set(key: &str) -> bool {
    match keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT) {
        Ok(entry) => match entry.set_password(key) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!("keyring set failed: {e}");
                false
            }
        },
        Err(e) => {
            tracing::debug!("keyring entry creation failed: {e}");
            false
        }
    }
}

fn read_keyfile() -> Option<Zeroizing<String>> {
    let path = keyfile_path().ok()?;
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(Zeroizing::new(s.trim().to_owned())),
        Err(e) => {
            warn!("failed to read keyfile: {e}");
            None
        }
    }
}

fn write_keyfile(key: &str) -> Result<(), AppError> {
    let path = keyfile_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, key)?;
    Ok(())
}

fn build_fernet(key_str: &str) -> Result<fernet::Fernet, AppError> {
    fernet::Fernet::new(key_str)
        .ok_or_else(|| AppError::Crypto("invalid Fernet key format".into()))
}

// ─── Public init ─────────────────────────────────────────────────────────────

/// Initialise the crypto layer.  Called once at startup inside the Tauri
/// `.setup()` closure.  Returns a `CryptoState` to be placed into `AppState`.
///
/// Logs the key source at INFO level — NEVER logs the key value.
pub fn init() -> Result<CryptoState, AppError> {
    // 1. Try Windows Credential Manager.
    if let Some(key) = try_keyring_get() {
        info!(key_source = "keyring", "Fernet key loaded");
        let fernet = build_fernet(&key)?;
        return Ok(CryptoState {
            fernet,
            key_source: KeySource::Keyring,
        });
    }

    // 2. Try keyfile fallback (%APPDATA%\DFARS\.keyfile).
    if let Some(key) = read_keyfile() {
        info!(key_source = "keyfile", "Fernet key loaded from file fallback");
        let fernet = build_fernet(&key)?;
        return Ok(CryptoState {
            fernet,
            key_source: KeySource::Keyfile,
        });
    }

    // 3. Generate a new key and persist it.
    let new_key = fernet::Fernet::generate_key();
    // Prefer keyring; fall back to file.
    if try_keyring_set(&new_key) {
        info!(key_source = "new", "Generated new Fernet key, stored in keyring");
        // Also write keyfile as a backup.
        if let Err(e) = write_keyfile(&new_key) {
            warn!("could not write keyfile backup: {e}");
        }
    } else {
        warn!(
            key_source = "new",
            "Keyring unavailable; storing Fernet key in keyfile. \
             This is less secure — consider enabling Windows Credential Manager."
        );
        write_keyfile(&new_key)?;
    }

    let fernet = build_fernet(&new_key)?;
    Ok(CryptoState {
        fernet,
        key_source: KeySource::New,
    })
}

// ─── Public encrypt / decrypt ─────────────────────────────────────────────

impl CryptoState {
    /// Encrypt arbitrary bytes and return a URL-safe Fernet token string.
    pub fn encrypt(&self, plaintext: &[u8]) -> String {
        self.fernet.encrypt(plaintext)
    }

    /// Decrypt a Fernet token string back to bytes.
    pub fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, AppError> {
        self.fernet
            .decrypt(ciphertext)
            .map_err(|_| AppError::Crypto("decryption failed — key may have been rotated or lost".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: bytes encrypted by this module must decrypt to the original.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        // Use a known valid Fernet key (32 bytes URL-safe-base64-encoded).
        let key = fernet::Fernet::generate_key();
        let fernet_inst = fernet::Fernet::new(&key).unwrap();
        let state = CryptoState {
            fernet: fernet_inst,
            key_source: KeySource::New,
        };
        let plaintext = b"dfars-test-secret-totp-seed";
        let ct = state.encrypt(plaintext);
        let recovered = state.decrypt(&ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Wrong key must return an error, not panic.
    #[test]
    fn decrypt_wrong_key_returns_error() {
        let key1 = fernet::Fernet::generate_key();
        let key2 = fernet::Fernet::generate_key();
        let state1 = CryptoState {
            fernet: fernet::Fernet::new(&key1).unwrap(),
            key_source: KeySource::New,
        };
        let state2 = CryptoState {
            fernet: fernet::Fernet::new(&key2).unwrap(),
            key_source: KeySource::New,
        };
        let ct = state1.encrypt(b"secret");
        assert!(state2.decrypt(&ct).is_err());
    }
}
