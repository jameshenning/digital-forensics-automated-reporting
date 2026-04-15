// Probe: open the real v1 forensics.db and call get_case / list_cases to
// isolate backend from frontend when the case-detail page fails in the GUI.
//
// Run: cargo run --example probe_v1_db

use dfars_desktop_lib::db::cases::{get_case, list_cases};
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a copy in std temp so we don't risk touching the real DB.
    let src = r"C:\Users\jhenn\AppData\Roaming\DFARS\forensics.db";
    let tmp_path = std::env::temp_dir().join("dfars_probe_forensics.db");
    if tmp_path.exists() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    std::fs::copy(src, &tmp_path)?;

    let url = format!("sqlite://{}?mode=rwc", tmp_path.display().to_string().replace('\\', "/"));
    eprintln!("Opening: {url}");

    let pool = SqlitePoolOptions::new().connect(&url).await?;

    eprintln!("=== list_cases(10, 0) ===");
    match list_cases(&pool, 10, 0).await {
        Ok(summaries) => {
            eprintln!("OK: {} summaries", summaries.len());
            for s in &summaries {
                eprintln!("  {} | {} | start={} | created={}", s.case_id, s.case_name, s.start_date, s.created_at);
            }
        }
        Err(e) => eprintln!("ERR: {e:?}"),
    }

    for case_id in ["2026-222343", "SMOKE-1", "X1"] {
        eprintln!("=== get_case({case_id}) ===");
        match get_case(&pool, case_id).await {
            Ok(detail) => {
                eprintln!("OK: {} | start={} | end={:?} | created={} | updated={}",
                    detail.case.case_id,
                    detail.case.start_date,
                    detail.case.end_date,
                    detail.case.created_at,
                    detail.case.updated_at);
                eprintln!("   tags={:?}", detail.tags);
            }
            Err(e) => eprintln!("ERR: {e:?}"),
        }
    }

    Ok(())
}
