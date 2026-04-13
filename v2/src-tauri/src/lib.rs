mod db;

use tauri::Manager;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Resolve %APPDATA%\DFARS\ — same paths v1 uses so existing DBs open unchanged.
            let app_data = app
                .path()
                .app_data_dir()
                .expect("failed to resolve AppData dir");

            // Ensure the directory exists (first launch on a fresh machine).
            std::fs::create_dir_all(&app_data)?;

            let forensics_path = app_data.join("forensics.db");
            let auth_path = app_data.join("auth.db");

            // Block on async DB init using Tauri's built-in tokio runtime.
            let app_db = tauri::async_runtime::block_on(async {
                db::init(&forensics_path, &auth_path).await
            })
            .expect("failed to initialise database");

            app.manage(app_db);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
