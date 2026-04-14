-- DFARS Desktop Authentication Schema
-- Stored in auth.db (separate from forensics.db so exports don't leak credentials)

PRAGMA foreign_keys = ON;

-- Users table
--
-- Single-user mode is enforced at the application layer (auth.create_user
-- refuses to create a second user). MFA columns are included up front so
-- Phase 3 can add TOTP without a schema migration.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,         -- Argon2id encoded hash (includes params + salt)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,              -- NULL if not locked

    -- Phase 3: MFA fields
    mfa_enabled INTEGER NOT NULL DEFAULT 0,   -- 0 = disabled, 1 = enabled
    totp_secret TEXT,                         -- Base32 TOTP secret (encrypted at rest via Fernet, see app.crypto)
    mfa_enrolled_at TIMESTAMP
);

-- Recovery codes table (Phase 3)
--
-- Each row stores the Argon2id hash of a single one-time recovery code.
-- On redemption, `used_at` is set and the code cannot be reused.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMP,                   -- NULL if unused
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id ON recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- API tokens table (Phase 4)
--
-- Bearer tokens that external integrations (Agent Zero plugin, etc.) use
-- to push data into DFARS Desktop via /api/v1/*. The plaintext token is
-- shown to the user exactly once at generation time; only the Argon2id
-- hash is persisted. token_preview holds the first ~10 chars so the user
-- can identify a specific token in the management UI without revealing it.
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,                  -- user-facing label, e.g. "Agent Zero"
    token_hash TEXT NOT NULL,            -- Argon2id hash of plaintext token
    token_preview TEXT NOT NULL,         -- first ~10 chars of plaintext for UI display
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
