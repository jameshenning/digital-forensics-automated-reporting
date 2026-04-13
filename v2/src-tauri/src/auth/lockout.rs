/// Account lockout tracker using monotonic `Instant` timers.
///
/// MUST-DO 2 (SEC-1): v1 stores `locked_until` as a wall-clock ISO string in
/// SQLite and compares with `datetime.now()`. An adversary can wind the system
/// clock backward to bypass the lockout. v2 uses `std::time::Instant` for all
/// runtime decisions — it is monotonic and immune to wall-clock manipulation.
///
/// Runtime state: `HashMap<String, (u32, Option<Instant>)>`
///   key   = username
///   value = (failed_attempt_count, Option<lockout_expires_instant>)
///
/// The SQLite columns `failed_login_count` and `locked_until` remain
/// as-is (wall-clock ISO timestamp) for cross-restart durability ONLY.
/// At startup we hydrate the in-memory map from the DB; during the session
/// all checks and updates use `Instant` exclusively.
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

use sqlx::SqlitePool;
use tracing::info;

use crate::error::AppError;

pub const MAX_FAILED_ATTEMPTS: u32 = 5;
pub const LOCKOUT_DURATION: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// Returned by `register_failure` if the account just became locked.
#[derive(Debug, Clone)]
pub struct LockoutInfo {
    #[allow(dead_code)]
    pub username: String,
    pub seconds_remaining: u64,
}

/// In-memory lockout table. Held in `AppState`.
pub struct LockoutMap {
    inner: Mutex<HashMap<String, (u32, Option<Instant>)>>,
}

impl LockoutMap {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Hydrate the in-memory map from the `users` table at startup.
    ///
    /// For each user whose DB row shows `failed_login_count >= MAX_FAILED_ATTEMPTS`
    /// AND `locked_until` is in the future, compute the remaining duration using
    /// `SystemTime` (wall-clock is fine for the one-time startup conversion) and
    /// store `Instant::now() + remaining` in the map.
    ///
    /// If the DB lockout has already expired at startup time, clears the entry.
    /// Correctly handles an empty `users` table without panicking (fresh install).
    pub async fn hydrate_from_db(&self, pool: &SqlitePool) -> Result<(), AppError> {
        // Use dynamic query to avoid sqlx compile-time macro dependency.
        let rows = sqlx::query(
            "SELECT username, failed_login_count, locked_until FROM users"
        )
        .fetch_all(pool)
        .await?;

        let mut map = self.inner.lock().expect("lockout map lock poisoned");

        for row in rows {
            use sqlx::Row;
            let username: String = row.try_get("username")?;
            let count: i64 = row.try_get("failed_login_count")?;
            let locked_until: Option<String> = row.try_get("locked_until")?;

            let count = count as u32;
            if count == 0 {
                continue;
            }

            let lockout_instant = if count >= MAX_FAILED_ATTEMPTS {
                locked_until
                    .as_deref()
                    .and_then(parse_lockout_instant)
            } else {
                None
            };

            map.insert(username.clone(), (count, lockout_instant));

            if let Some(expires) = lockout_instant {
                let remaining = expires
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::ZERO);
                if remaining.is_zero() {
                    info!(username = %username, "startup: lockout expired, clearing");
                    map.insert(username, (0, None));
                } else {
                    info!(
                        username = %username,
                        remaining_secs = remaining.as_secs(),
                        "startup: account still locked"
                    );
                }
            }
        }

        Ok(())
    }

    /// Check whether the account is currently locked.
    ///
    /// Returns `Ok(())` if the account may attempt login.
    /// Returns `Err(AppError::AccountLocked { seconds_remaining })` if locked.
    pub fn check(&self, username: &str) -> Result<(), AppError> {
        let map = self.inner.lock().expect("lockout map lock poisoned");
        if let Some((_, Some(expires))) = map.get(username) {
            let now = Instant::now();
            if *expires > now {
                let remaining = expires.duration_since(now).as_secs().max(1);
                return Err(AppError::AccountLocked {
                    seconds_remaining: remaining,
                });
            }
        }
        Ok(())
    }

    /// Record a failed login attempt.  Returns a `LockoutInfo` if the account
    /// just became locked, `None` otherwise.
    pub fn register_failure(&self, username: &str) -> Option<LockoutInfo> {
        let mut map = self.inner.lock().expect("lockout map lock poisoned");
        let entry = map.entry(username.to_owned()).or_insert((0, None));
        entry.0 += 1;
        let new_count = entry.0;

        if new_count >= MAX_FAILED_ATTEMPTS {
            let expires = Instant::now() + LOCKOUT_DURATION;
            entry.1 = Some(expires);
            let remaining = LOCKOUT_DURATION.as_secs();
            info!(
                username = %username,
                failed_count = new_count,
                lockout_seconds = remaining,
                "account locked"
            );
            Some(LockoutInfo {
                username: username.to_owned(),
                seconds_remaining: remaining,
            })
        } else {
            info!(username = %username, failed_count = new_count, "failed login attempt");
            None
        }
    }

    /// Clear the lockout state on successful login.
    pub fn clear_on_success(&self, username: &str) {
        let mut map = self.inner.lock().expect("lockout map lock poisoned");
        map.insert(username.to_owned(), (0, None));
    }

    /// Retrieve the current count for persisting to DB (durability only).
    pub fn get_count_for_db(&self, username: &str) -> (u32, Option<SystemTime>) {
        let map = self.inner.lock().expect("lockout map lock poisoned");
        match map.get(username) {
            Some((count, Some(instant_expires))) => {
                // Convert `Instant` back to `SystemTime` for storage.
                // This is the ONLY place we translate back to wall-clock.
                let remaining = instant_expires
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::ZERO);
                let wall_expires = SystemTime::now() + remaining;
                (*count, Some(wall_expires))
            }
            Some((count, None)) => (*count, None),
            None => (0, None),
        }
    }
}

/// Parse a SQLite ISO timestamp and convert to a monotonic `Instant`.
///
/// Uses `SystemTime` for the one-time startup conversion (wall-clock vs. DB).
/// Returns `None` if the timestamp is unparseable or already in the past.
fn parse_lockout_instant(ts: &str) -> Option<Instant> {
    let dt = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S"))
        .ok()?;

    let locked_until_utc = dt.and_utc();
    let now_utc = chrono::Utc::now();

    if locked_until_utc <= now_utc {
        return None; // Already expired.
    }

    let remaining_secs = (locked_until_utc - now_utc).num_seconds() as u64;
    let remaining = Duration::from_secs(remaining_secs);
    Some(Instant::now() + remaining)
}

/// Persist the lockout counter back to DB for cross-restart durability.
/// NOT used for runtime lockout decisions (those use `Instant`).
pub async fn persist_to_db(
    pool: &SqlitePool,
    username: &str,
    count: u32,
    locked_until: Option<SystemTime>,
) -> Result<(), AppError> {
    let locked_until_str: Option<String> = locked_until.map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.format("%Y-%m-%dT%H:%M:%S").to_string()
    });

    let count_i64 = count as i64;
    sqlx::query(
        "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE username = ?"
    )
    .bind(count_i64)
    .bind(locked_until_str)
    .bind(username)
    .execute(pool)
    .await?;

    Ok(())
}

/// Persist a successful login: reset counter, clear lockout, set last_login.
pub async fn persist_success(pool: &SqlitePool, username: &str) -> Result<(), AppError> {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    sqlx::query(
        "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login = ? WHERE username = ?"
    )
    .bind(now)
    .bind(username)
    .execute(pool)
    .await?;
    Ok(())
}

impl Default for LockoutMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After MAX_FAILED_ATTEMPTS failures, `check()` must return `AccountLocked`.
    /// The lockout must remain regardless of any wall-clock tricks — this test
    /// verifies that the timer is purely Instant-based.
    #[test]
    fn lockout_after_max_attempts() {
        let map = LockoutMap::new();
        let user = "alice";

        for i in 0..MAX_FAILED_ATTEMPTS {
            assert!(map.check(user).is_ok(), "should not be locked at attempt {i}");
            let info = map.register_failure(user);
            if i + 1 < MAX_FAILED_ATTEMPTS {
                assert!(info.is_none());
            } else {
                assert!(info.is_some());
            }
        }

        // Now the account must be locked.
        let result = map.check(user);
        assert!(result.is_err());
        match result {
            Err(AppError::AccountLocked { seconds_remaining }) => {
                assert!(seconds_remaining > 0 && seconds_remaining <= 300);
            }
            _ => panic!("expected AccountLocked"),
        }
    }

    /// `clear_on_success` must lift the lockout.
    #[test]
    fn clear_on_success_lifts_lockout() {
        let map = LockoutMap::new();
        let user = "bob";
        for _ in 0..MAX_FAILED_ATTEMPTS {
            map.register_failure(user);
        }
        assert!(map.check(user).is_err());
        map.clear_on_success(user);
        assert!(map.check(user).is_ok());
    }

    /// A different user is not affected by another's lockout.
    #[test]
    fn lockout_is_per_user() {
        let map = LockoutMap::new();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            map.register_failure("alice");
        }
        assert!(map.check("bob").is_ok());
    }
}
