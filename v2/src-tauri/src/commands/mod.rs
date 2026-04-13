/// Tauri command surface — all `#[tauri::command]` functions live in sub-modules.
///
/// ╔══════════════════════════════════════════════════════════════════════════════╗
/// ║  MANDATORY SESSION GUARD — READ BEFORE ADDING A COMMAND                   ║
/// ╠══════════════════════════════════════════════════════════════════════════════╣
/// ║                                                                              ║
/// ║  EVERY Tauri command that reads or mutates ANY of the tables listed below  ║
/// ║  MUST call `auth::session::require_session(state, token)` as its FIRST     ║
/// ║  line of code.  This is MUST-DO 3 from SEC-1 and is the only thing         ║
/// ║  standing between an unauthenticated WebView script and legally-significant ║
/// ║  chain-of-custody data.                                                     ║
/// ║                                                                              ║
/// ║  Tables that require the guard:                                              ║
/// ║    forensics.db:                                                             ║
/// ║      - chain_of_custody                                                     ║
/// ║      - evidence                                                              ║
/// ║      - hash_verification                                                    ║
/// ║      - tool_usage                                                           ║
/// ║      - analysis_notes                                                       ║
/// ║      - entities                                                              ║
/// ║      - entity_links                                                         ║
/// ║      - case_events                                                          ║
/// ║      - evidence_files                                                       ║
/// ║      - evidence_analyses                                                    ║
/// ║      - case_shares                                                          ║
/// ║      - cases (all mutations)                                                ║
/// ║      - case_tags (all mutations)                                            ║
/// ║    auth.db:                                                                  ║
/// ║      - users (any mutation except login/setup flow)                         ║
/// ║      - recovery_codes                                                       ║
/// ║      - api_tokens                                                           ║
/// ║    config.json (all mutations)                                              ║
/// ║                                                                              ║
/// ║  If you add a new command that touches any of these, you MUST:             ║
/// ║    1. Call `require_session(state, token)?` as the FIRST statement.        ║
/// ║    2. Add a negative test confirming `AppError::Unauthorized` when         ║
/// ║       no/invalid session token is provided.                                 ║
/// ║    3. Update this comment block if you add a new table.                    ║
/// ║                                                                              ║
/// ╚══════════════════════════════════════════════════════════════════════════════╝

pub mod auth_cmd;
pub mod cases_cmd;
pub mod files_cmd;
pub mod records_cmd;
pub mod reports_cmd;
pub mod system_cmd;
