/// `AppState` — single shared state struct managed by Tauri.
///
/// Every Tauri command receives `State<Arc<AppState>>` and holds:
///   - `db`       — two SQLite pools (forensics.db + auth.db)
///   - `crypto`   — Fernet key + encrypt/decrypt methods
///   - `lockout`  — monotonic in-memory failed-attempt tracker (MUST-DO 2)
///   - `sessions` — in-memory session map (MUST-DO 3)
///   - `dummy_hash` — pre-computed Argon2 hash for enumeration guard
use std::sync::Arc;

use crate::{
    auth::{argon, lockout::LockoutMap, session::SessionState},
    crypto::CryptoState,
    db::AppDb,
};

pub struct AppState {
    pub db: AppDb,
    pub crypto: CryptoState,
    pub lockout: LockoutMap,
    pub sessions: SessionState,
    /// Pre-hashed dummy value for constant-time username enumeration guard.
    /// Generated at startup with the same Argon2 params as real passwords.
    pub dummy_hash: String,
}

impl AppState {
    /// Construct a new `AppState`.  Called inside Tauri's `.setup()` closure.
    pub fn new(db: AppDb, crypto: CryptoState) -> Self {
        let dummy_hash = argon::make_dummy_hash();
        Self {
            db,
            crypto,
            lockout: LockoutMap::new(),
            sessions: SessionState::new(),
            dummy_hash,
        }
    }
}

/// Type alias so commands don't need to spell out the full type.
/// Used by future command modules.
#[allow(dead_code)]
pub type SharedState = Arc<AppState>;
