use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, SqlitePool};
use std::path::Path;

/// Holds the two connection pools — one per SQLite file.
/// Matches v1's two-DB layout: forensics.db (case data) and auth.db (credentials).
pub struct AppDb {
    pub forensics: SqlitePool,
    pub auth: SqlitePool,
}

/// Open (or create) a single SQLite pool and run the given embedded migrations.
async fn open_pool(db_path: &Path, migrator: sqlx::migrate::Migrator) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;

    migrator.run(&pool).await?;

    Ok(pool)
}

/// Initialize both DB pools and apply all pending migrations.
/// Called once at app startup inside the `.setup()` closure.
pub async fn init(forensics_path: &Path, auth_path: &Path) -> Result<AppDb, sqlx::Error> {
    let forensics_migrator = sqlx::migrate!("./migrations/forensics");
    let auth_migrator = sqlx::migrate!("./migrations/auth");

    let forensics = open_pool(forensics_path, forensics_migrator).await?;
    let auth = open_pool(auth_path, auth_migrator).await?;

    Ok(AppDb { forensics, auth })
}
