/// `AppState` — single shared state struct managed by Tauri.
///
/// Every Tauri command receives `State<Arc<AppState>>` and holds:
///   - `db`          — two SQLite pools (forensics.db + auth.db)
///   - `crypto`      — Fernet key + encrypt/decrypt methods
///   - `lockout`     — monotonic in-memory failed-attempt tracker (MUST-DO 2)
///   - `sessions`    — in-memory session map (MUST-DO 3)
///   - `dummy_hash`  — pre-computed Argon2 hash for enumeration guard
///   - `config`      — loaded `AppConfig` (Phase 5)
///   - `config_path` — path to `config.json` for persistence (Phase 5)
///   - `agent_zero`  — Agent Zero outbound client state (Phase 5)
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::{
    agent_zero::AgentZeroState,
    auth::{argon, lockout::LockoutMap, session::SessionState},
    config::AppConfig,
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

    // ─── Phase 5 additions ───────────────────────────────────────────────────

    /// Loaded app configuration. Mutations go through `config::save()` then
    /// re-construct this field; commands read it via `state.config`.
    ///
    /// Note: currently stored as a value (not `RwLock`) because config mutations
    /// during runtime are handled by the integrations commands which reload the
    /// binary on next startup.  If live-reload becomes a requirement, wrap in
    /// `Arc<RwLock<AppConfig>>`.
    pub config: AppConfig,

    /// Absolute path to `config.json` — used by settings commands to persist.
    pub config_path: PathBuf,

    /// Lazily-initialized Agent Zero outbound client.
    pub agent_zero: AgentZeroState,

    /// Runtime-mutable OSINT consent flag. Initialized from
    /// `config.shown_ai_osint_consent` at startup; flipped to true in-memory
    /// when `settings_acknowledge_osint_consent` succeeds. This avoids the
    /// known in-memory-config staleness issue where config mutations don't
    /// take effect until the next app launch. Readers should prefer this
    /// atomic over `state.config.shown_ai_osint_consent`.
    pub osint_consent_runtime: Arc<AtomicBool>,
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
            config: AppConfig::default(),
            config_path: PathBuf::new(),
            agent_zero: AgentZeroState::new(),
            osint_consent_runtime: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Construct with explicit config (used at startup after loading config.json).
    pub fn new_with_config(
        db: AppDb,
        crypto: CryptoState,
        config: AppConfig,
        config_path: PathBuf,
        agent_zero: AgentZeroState,
    ) -> Self {
        let dummy_hash = argon::make_dummy_hash();
        let osint_consent_runtime = Arc::new(AtomicBool::new(config.shown_ai_osint_consent));
        Self {
            db,
            crypto,
            lockout: LockoutMap::new(),
            sessions: SessionState::new(),
            dummy_hash,
            config,
            config_path,
            agent_zero,
            osint_consent_runtime,
        }
    }

    /// Check the runtime OSINT consent flag. Prefer this over reading
    /// `config.shown_ai_osint_consent` directly — the atomic reflects
    /// in-session acknowledgments without requiring an app restart.
    pub fn osint_consent_granted(&self) -> bool {
        self.osint_consent_runtime.load(Ordering::Relaxed)
    }

    /// Set the runtime OSINT consent flag. Call this AFTER persisting
    /// `config.shown_ai_osint_consent = true` to disk.
    pub fn set_osint_consent_granted(&self, v: bool) {
        self.osint_consent_runtime.store(v, Ordering::Relaxed);
    }
}

/// Type alias so commands don't need to spell out the full type.
pub type SharedState = Arc<AppState>;
