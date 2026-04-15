/// axum inbound REST API server — SEC-4/5 MUST-DOs 1–8.
///
/// Runs on a separate tokio task sharing `Arc<AppState>` with Tauri commands.
/// The `sqlx::SqlitePool` inside `AppState` is `Send + Sync`, so no extra
/// synchronisation is needed.
///
/// ## Security controls implemented here
///
/// | MUST-DO | Control                                           | Location                 |
/// |---|---|---|
/// | 1       | Timing-oracle mitigation (dummy Argon2 on miss)   | bearer_auth_middleware   |
/// | 2       | Token-space isolation (sess_ rejected at axum)    | bearer_auth_middleware   |
/// | 3       | JSON depth limit (max 32)                         | BoundedJson extractor    |
/// | 4       | Per-route request body limits                     | route layers             |
/// | 5       | Bind-host gate (loopback-only unless explicit opt-in)| start()              |
/// | 6       | Agent Zero URL allowlist                          | agent_zero.rs            |
/// | 7       | Agent Zero response body limits                   | agent_zero.rs            |
/// | 8       | Audit actor format `api_token:<name>`             | every mutation handler   |
///
/// ## No CORS (sec-4-5-network-review.md §2.15)
///
/// This is a machine-to-machine API called by Agent Zero (a Python process).
/// CORS headers would incorrectly enable browser callers from any origin.
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::TcpListener, sync::oneshot};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info, warn};

use crate::audit;
use crate::auth::tokens::VerifiedToken;
use crate::db::{analysis, cases, custody, evidence, evidence_files, hashes, tools};
use crate::error::AppError;
use crate::state::AppState;

// ─── Body limits per SEC-5 MUST-DO 4 ──────────────────────────────────────────

const BODY_LIMIT_GLOBAL:   usize = 64 * 1024;       // 64 KiB — global floor
const BODY_LIMIT_CASE:     usize = 16 * 1024;       // 16 KiB
const BODY_LIMIT_EVIDENCE: usize = 16 * 1024;       // 16 KiB
const BODY_LIMIT_CUSTODY:  usize = 8  * 1024;       //  8 KiB
const BODY_LIMIT_HASHES:   usize = 8  * 1024;       //  8 KiB
const BODY_LIMIT_TOOLS:    usize = 64 * 1024;       // 64 KiB (command_used can be long)
const BODY_LIMIT_ANALYSIS: usize = 32 * 1024;       // 32 KiB

// ─── JSON depth limit per SEC-5 MUST-DO 3 ────────────────────────────────────

const JSON_MAX_DEPTH: usize = 32;

/// Check the maximum nesting depth of a JSON byte slice without fully parsing it.
///
/// Counts unescaped `{` and `[` characters. If the depth exceeds `max`, returns
/// `false`. This is O(n) in body size and runs before serde_json deserialization,
/// preventing stack-overflow via deeply-nested crafted input (MUST-DO 3).
pub fn check_json_depth(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;

    for &b in bytes {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            match b {
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return false;
                }
            }
            b'}' | b']' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            _ => {}
        }
    }
    true
}

// ─── API error shape (SEC-5 MUST-DO — §2.13) ─────────────────────────────────

/// Sanitized error response. Raw internal errors (sqlx strings, file paths, hashes)
/// NEVER appear in this struct — they are logged at ERROR level only.
#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
    code: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    details: Value,
}

impl ApiError {
    fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
            details: Value::Null,
        }
    }
    fn unauthorized() -> Self {
        Self::new("Unauthorized", "UNAUTHORIZED")
    }
    fn not_found() -> Self {
        Self::new("Not found", "NOT_FOUND")
    }
    fn internal() -> Self {
        Self::new("Internal error", "INTERNAL_ERROR")
    }
    fn payload_too_large() -> Self {
        Self::new("Request body too large", "PAYLOAD_TOO_LARGE")
    }
    fn json_depth() -> Self {
        Self::new("JSON nesting depth exceeds maximum", "JSON_DEPTH_LIMIT")
    }
    fn validation(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        Self {
            error: msg.clone(),
            code: "VALIDATION_ERROR".into(),
            details: serde_json::json!({ "message": msg }),
        }
    }
    fn conflict() -> Self {
        Self::new("Resource already exists", "CONFLICT")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code.as_str() {
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "CONFLICT" => StatusCode::CONFLICT,
            "VALIDATION_ERROR" => StatusCode::UNPROCESSABLE_ENTITY,
            "PAYLOAD_TOO_LARGE" => StatusCode::PAYLOAD_TOO_LARGE,
            "JSON_DEPTH_LIMIT" => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

/// Map `AppError` to `ApiError` — sanitizes all internal details.
impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        match &e {
            AppError::Unauthorized | AppError::InvalidCredentials => Self::unauthorized(),
            AppError::CaseNotFound { .. } | AppError::EvidenceNotFound { .. }
            | AppError::EvidenceFileNotFound { .. } => Self::not_found(),
            AppError::CaseAlreadyExists { .. } | AppError::EvidenceAlreadyExists { .. } => {
                Self::conflict()
            }
            AppError::ValidationError { message, .. } => Self::validation(message.clone()),
            AppError::PayloadTooLarge { .. } => Self::payload_too_large(),
            // Internal errors — log but do not surface to caller.
            _ => {
                error!(error = ?e, "axum handler returned internal error");
                Self::internal()
            }
        }
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// ─── Server handle ────────────────────────────────────────────────────────────

pub struct AxumHandle {
    pub shutdown_tx: oneshot::Sender<()>,
    pub join: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for AxumHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AxumHandle").finish_non_exhaustive()
    }
}

// ─── Startup / shutdown ───────────────────────────────────────────────────────

/// Start the axum server. Returns a handle for graceful shutdown.
///
/// SEC-5 MUST-DO 5: bind-host gate — refuses non-loopback unless
/// `config.allow_network_bind = true`.
pub async fn start(
    state: Arc<AppState>,
    bind_host: &str,
    port: u16,
) -> Result<AxumHandle, AppError> {
    // Validate bind_host values.
    if bind_host != "127.0.0.1" && bind_host != "0.0.0.0" {
        return Err(AppError::NetworkBindRefused {
            bind_host: bind_host.to_owned(),
        });
    }

    // Non-loopback requires the explicit opt-in flag.
    if bind_host != "127.0.0.1" && !state.config.allow_network_bind {
        return Err(AppError::NetworkBindRefused {
            bind_host: bind_host.to_owned(),
        });
    }

    // Log + audit any non-loopback bind.
    if bind_host != "127.0.0.1" {
        warn!(
            bind_host,
            "axum server binding to {} — reachable from the local network. \
             Ensure API tokens are not exposed.",
            bind_host
        );
        audit::log_auth(
            "SYSTEM",
            audit::API_SERVER_NONLOOPBACK_BIND,
            &format!(
                "API server started with non-loopback bind address {}:{}",
                bind_host, port
            ),
        );
    }

    let addr: SocketAddr = format!("{bind_host}:{port}")
        .parse()
        .map_err(|e| AppError::Internal(format!("invalid bind address: {e}")))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::Internal(format!("TcpListener::bind failed: {e}")))?;

    let bound_addr = listener
        .local_addr()
        .map_err(|e| AppError::Internal(format!("local_addr failed: {e}")))?;
    info!(addr = %bound_addr, "axum REST API listening");

    let router = build_router(state);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let join = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
                info!("axum REST API shutting down");
            })
            .await
            .unwrap_or_else(|e| error!("axum serve error: {e}"));
    });

    Ok(AxumHandle { shutdown_tx, join })
}

/// Signal graceful shutdown and await the server task.
pub async fn stop(handle: AxumHandle) -> Result<(), AppError> {
    let _ = handle.shutdown_tx.send(());
    handle
        .join
        .await
        .map_err(|e| AppError::Internal(format!("axum join failed: {e}")))?;
    Ok(())
}

// ─── Router construction ──────────────────────────────────────────────────────

fn build_router(state: Arc<AppState>) -> Router {
    // Per-route body limits: applied via DefaultBodyLimit on individual routes.
    // Global floor applied via RequestBodyLimitLayer at the layer stack level.
    // In axum 0.7, per-route limits use DefaultBodyLimit::max() as a route layer.
    Router::new()
        // Health / identity
        .route("/api/v1/whoami", get(whoami))
        // Cases CRUD
        .route("/api/v1/cases", get(list_cases))
        .route(
            "/api/v1/cases",
            post(create_case).layer(DefaultBodyLimit::max(BODY_LIMIT_CASE)),
        )
        .route("/api/v1/cases/:case_id", get(get_case))
        .route(
            "/api/v1/cases/:case_id",
            axum::routing::patch(patch_case).layer(DefaultBodyLimit::max(BODY_LIMIT_CASE)),
        )
        // Evidentiary append-only routes (SEC: append-only by design, no DELETE)
        .route(
            "/api/v1/cases/:case_id/evidence",
            post(add_evidence).layer(DefaultBodyLimit::max(BODY_LIMIT_EVIDENCE)),
        )
        .route(
            "/api/v1/cases/:case_id/custody",
            post(add_custody).layer(DefaultBodyLimit::max(BODY_LIMIT_CUSTODY)),
        )
        .route(
            "/api/v1/cases/:case_id/hashes",
            post(add_hash).layer(DefaultBodyLimit::max(BODY_LIMIT_HASHES)),
        )
        .route(
            "/api/v1/cases/:case_id/tools",
            post(add_tool).layer(DefaultBodyLimit::max(BODY_LIMIT_TOOLS)),
        )
        .route(
            "/api/v1/cases/:case_id/analysis",
            post(add_analysis).layer(DefaultBodyLimit::max(BODY_LIMIT_ANALYSIS)),
        )
        // Report + file download (read-only)
        .route("/api/v1/cases/:case_id/report", get(get_report))
        .route(
            "/api/v1/cases/:case_id/evidence/:evidence_id/files/:file_id/download",
            get(download_file),
        )
        // Global middleware: bearer auth runs on every request.
        // Global body limit floor: 64 KiB.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_GLOBAL))
        .with_state(state)
}

// ─── Bearer auth middleware (SEC-5 MUST-DO 1 + 2) ────────────────────────────

/// Bearer token authentication middleware.
///
/// MUST-DO 1: Timing-oracle mitigation.  When no row matches the `token_preview`,
/// `auth::tokens::dummy_verify(&state)` is called so the no-match path takes
/// ~100ms (same as a real Argon2 verify), eliminating the timing distinguisher.
///
/// MUST-DO 2: Token-space isolation.  Session tokens (`sess_...`) are explicitly
/// rejected here.  The inverse (API tokens rejected by `require_session`) is
/// enforced in `auth/session.rs`.  These namespaces must NEVER intersect.
async fn bearer_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let token = extract_bearer(req.headers());

    let token = match token {
        Some(t) => t,
        None => return Err(ApiError::unauthorized()),
    };

    // MUST-DO 2: Reject session tokens at the axum layer.
    // Run a dummy Argon2 call first to avoid timing discrepancy
    // between "bad prefix" and "no preview match" paths.
    if token.starts_with("sess_") || !token.starts_with("dfars_") {
        // Close timing oracle: run dummy Argon2 regardless of prefix.
        let _ = crate::auth::tokens::dummy_verify(&state).await;
        return Err(ApiError::unauthorized());
    }

    match crate::auth::tokens::verify(&state.db.auth, &token).await {
        Ok(Some(verified)) => {
            req.extensions_mut().insert(verified);
            Ok(next.run(req).await)
        }
        Ok(None) => Err(ApiError::unauthorized()),
        Err(e) => {
            error!(error = ?e, "bearer_auth_middleware: verify returned error");
            Err(ApiError::internal())
        }
    }
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?;
    let s = val.to_str().ok()?;
    let token = s.strip_prefix("Bearer ")?;
    Some(token.to_owned())
}

// ─── BoundedJson extractor (SEC-5 MUST-DO 3) ─────────────────────────────────

/// Custom `FromRequest` extractor that:
///   1. Reads the body bytes.
///   2. Runs `check_json_depth` (max 32 levels).
///   3. Deserializes with `serde_json::from_slice`.
///
/// Replaces vanilla `Json<T>` on all POST/PATCH handlers.
struct BoundedJson<T>(pub T);

#[axum::async_trait]
impl<T, S> axum::extract::FromRequest<S> for BoundedJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| ApiError::payload_too_large())?;

        if !check_json_depth(&bytes, JSON_MAX_DEPTH) {
            return Err(ApiError::json_depth());
        }

        let val: T = serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::validation(format!("JSON parse error: {e}")))?;

        Ok(BoundedJson(val))
    }
}

// ─── Route handlers ───────────────────────────────────────────────────────────

async fn whoami(
    Extension(token): Extension<VerifiedToken>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(serde_json::json!({
        "token_name": token.name,
        "username": token.username,
    })))
}

// ── Cases ──────────────────────────────────────────────────────────────────────

/// HTTP-flat wrapper around `cases::CaseDetail`.
///
/// `cases::CaseDetail` serializes as `{"case": {...}, "tags": [...]}` (nested)
/// for the Tauri IPC frontend. The external REST API consumers (Agent Zero,
/// v1-compat clients) expect all Case fields at the top level alongside
/// `tags`, so we flatten here just for HTTP responses.
#[derive(Serialize)]
struct FlatCaseDetail {
    #[serde(flatten)]
    case: cases::Case,
    tags: Vec<String>,
}

impl From<cases::CaseDetail> for FlatCaseDetail {
    fn from(d: cases::CaseDetail) -> Self {
        Self { case: d.case, tags: d.tags }
    }
}

async fn list_cases(
    State(state): State<Arc<AppState>>,
    Extension(_token): Extension<VerifiedToken>,
) -> ApiResult<Vec<cases::CaseSummary>> {
    // Default: return first 1000 cases (v1 parity — no pagination in the REST API).
    let rows = cases::list_cases(&state.db.forensics, 1000, 0)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(rows))
}

async fn create_case(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    BoundedJson(input): BoundedJson<cases::CaseInput>,
) -> Result<(StatusCode, Json<FlatCaseDetail>), ApiError> {
    let actor = format!("api_token:{}", token.name); // MUST-DO 8
    let detail = cases::create_case(&state.db.forensics, &input)
        .await
        .map_err(ApiError::from)?;

    audit::log_case(&detail.case.case_id, &actor, audit::CASE_CREATED, "via axum API");
    Ok((StatusCode::CREATED, Json(FlatCaseDetail::from(detail))))
}

async fn get_case(
    State(state): State<Arc<AppState>>,
    Extension(_token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
) -> ApiResult<FlatCaseDetail> {
    let detail = cases::get_case(&state.db.forensics, &case_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(FlatCaseDetail::from(detail)))
}

#[derive(Debug, Deserialize)]
struct CasePatch {
    pub case_name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub classification: Option<String>,
    pub agency: Option<String>,
}

async fn patch_case(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
    BoundedJson(patch): BoundedJson<CasePatch>,
) -> ApiResult<FlatCaseDetail> {
    // Load existing, apply patch fields.
    let existing = cases::get_case(&state.db.forensics, &case_id)
        .await
        .map_err(ApiError::from)?;

    let mut input = cases::CaseInput {
        case_id: case_id.clone(),
        case_name: patch.case_name.unwrap_or(existing.case.case_name.clone()),
        description: patch.description.or(existing.case.description.clone()),
        investigator: existing.case.investigator.clone(),
        agency: patch.agency.or(existing.case.agency.clone()),
        // Case.start_date / end_date are now Strings (v1-compat); parse back to
        // NaiveDate for CaseInput. Existing values came from v2's own writes via
        // an ISO-formatted string, so these should always parse. v1-legacy rows
        // may have space-separated datetimes — try both formats.
        start_date: chrono::NaiveDate::parse_from_str(&existing.case.start_date, "%Y-%m-%d")
            .or_else(|_| {
                chrono::NaiveDateTime::parse_from_str(&existing.case.start_date, "%Y-%m-%d %H:%M:%S")
                    .map(|dt| dt.date())
            })
            .or_else(|_| {
                chrono::NaiveDateTime::parse_from_str(&existing.case.start_date, "%Y-%m-%d %H:%M:%S%.f")
                    .map(|dt| dt.date())
            })
            .map_err(|e| ApiError::from(AppError::Db(format!("invalid start_date: {e}"))))?,
        end_date: existing.case.end_date.as_ref().map(|s| {
            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").map(|dt| dt.date()))
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").map(|dt| dt.date()))
                .unwrap_or_else(|_| chrono::Local::now().date_naive())
        }),
        status: patch.status.or(Some(existing.case.status.clone())),
        priority: patch.priority.or(Some(existing.case.priority.clone())),
        classification: patch.classification.or(existing.case.classification.clone()),
        evidence_drive_path: existing.case.evidence_drive_path.clone(),
        tags: existing.tags.clone(),
    };
    // Ensure case_id is overridden by URL param.
    input.case_id = case_id.clone();

    let actor = format!("api_token:{}", token.name); // MUST-DO 8
    let detail = cases::update_case(&state.db.forensics, &case_id, &input)
        .await
        .map_err(ApiError::from)?;

    audit::log_case(&case_id, &actor, audit::CASE_UPDATED, "via axum API");
    Ok(Json(FlatCaseDetail::from(detail)))
}

// ── Evidence ───────────────────────────────────────────────────────────────────

async fn add_evidence(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
    BoundedJson(input): BoundedJson<evidence::EvidenceInput>,
) -> Result<(StatusCode, Json<evidence::Evidence>), ApiError> {
    let actor = format!("api_token:{}", token.name); // MUST-DO 8
    let ev = evidence::add_evidence(&state.db.forensics, &case_id, &input)
        .await
        .map_err(ApiError::from)?;
    audit::log_case(&case_id, &actor, audit::EVIDENCE_ADDED, &format!("evidence_id={}", ev.evidence_id));
    Ok((StatusCode::CREATED, Json(ev)))
}

// ── Custody ────────────────────────────────────────────────────────────────────
// The v1 API body for POST /cases/:case_id/custody includes `evidence_id`.
// We define an API-layer wrapper that carries evidence_id + the fields CustodyInput needs.

#[derive(Deserialize)]
struct CustodyApiBody {
    pub evidence_id: String,
    #[serde(flatten)]
    pub inner: custody::CustodyInput,
}

async fn add_custody(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
    BoundedJson(body): BoundedJson<CustodyApiBody>,
) -> Result<(StatusCode, Json<custody::CustodyEvent>), ApiError> {
    let actor = format!("api_token:{}", token.name); // MUST-DO 8
    let ev = custody::add_custody(&state.db.forensics, &body.evidence_id, &body.inner)
        .await
        .map_err(ApiError::from)?;
    audit::log_case(&case_id, &actor, audit::CUSTODY_ADDED, &format!("custody_id={}", ev.custody_id));
    Ok((StatusCode::CREATED, Json(ev)))
}

// ── Hashes ─────────────────────────────────────────────────────────────────────
// v1 body includes `evidence_id`.

#[derive(Deserialize)]
struct HashApiBody {
    pub evidence_id: String,
    #[serde(flatten)]
    pub inner: hashes::HashInput,
}

async fn add_hash(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
    BoundedJson(body): BoundedJson<HashApiBody>,
) -> Result<(StatusCode, Json<hashes::HashRecord>), ApiError> {
    let actor = format!("api_token:{}", token.name); // MUST-DO 8
    let record = hashes::add_hash(&state.db.forensics, &body.evidence_id, &body.inner)
        .await
        .map_err(ApiError::from)?;
    audit::log_case(&case_id, &actor, audit::HASH_ADDED, &format!("hash_id={}", record.hash_id));
    Ok((StatusCode::CREATED, Json(record)))
}

// ── Tools ──────────────────────────────────────────────────────────────────────

async fn add_tool(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
    BoundedJson(input): BoundedJson<tools::ToolInput>,
) -> Result<(StatusCode, Json<tools::ToolUsage>), ApiError> {
    let actor = format!("api_token:{}", token.name); // MUST-DO 8
    let record = tools::add_tool(&state.db.forensics, &case_id, &input)
        .await
        .map_err(ApiError::from)?;
    audit::log_case(&case_id, &actor, audit::TOOL_ADDED, &format!("tool_id={}", record.tool_id));
    Ok((StatusCode::CREATED, Json(record)))
}

// ── Analysis ───────────────────────────────────────────────────────────────────

async fn add_analysis(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
    BoundedJson(input): BoundedJson<analysis::AnalysisInput>,
) -> Result<(StatusCode, Json<analysis::AnalysisNote>), ApiError> {
    let actor = format!("api_token:{}", token.name); // MUST-DO 8
    let note = analysis::add_analysis(&state.db.forensics, &case_id, &input)
        .await
        .map_err(ApiError::from)?;
    audit::log_case(&case_id, &actor, audit::ANALYSIS_ADDED, &format!("note_id={}", note.note_id));
    Ok((StatusCode::CREATED, Json(note)))
}

// ── Report ─────────────────────────────────────────────────────────────────────

async fn get_report(
    State(state): State<Arc<AppState>>,
    Extension(_token): Extension<VerifiedToken>,
    Path(case_id): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    // Use preview_markdown — the same underlying generator as the Tauri command.
    let markdown = crate::reports::preview_markdown(&state, &case_id)
        .await
        .map_err(ApiError::from)?;
    Ok((
        StatusCode::OK,
        [("Content-Type", "text/markdown; charset=utf-8")],
        markdown,
    )
        .into_response())
}

// ── Evidence file download (SEC-5 §2.20) ──────────────────────────────────────

async fn download_file(
    State(state): State<Arc<AppState>>,
    Extension(token): Extension<VerifiedToken>,
    Path((case_id, evidence_id, file_id)): Path<(String, String, i64)>,
) -> Result<axum::response::Response, ApiError> {
    // Validate ownership chain.
    let _case = cases::get_case(&state.db.forensics, &case_id)
        .await
        .map_err(|_| ApiError::not_found())?;

    let ev = evidence_files::get_file(&state.db.forensics, file_id)
        .await
        .map_err(|_| ApiError::not_found())?;

    if ev.evidence_id != evidence_id {
        return Err(ApiError::not_found());
    }

    // Re-hash and compare to stored SHA-256 (SEC-5 §2.20 requirement 2).
    let (hash_verified, file_bytes) = read_and_verify_file(&ev).await?;

    if !hash_verified {
        error!(
            file_id,
            evidence_id = %evidence_id,
            "evidence file hash mismatch on axum download"
        );
        audit::log_case(
            &case_id,
            &format!("api_token:{}", token.name),
            audit::FILE_INTEGRITY_FAILURE,
            &format!("file_id={file_id} hash mismatch on axum download"),
        );
    }

    let original = ev.original_filename.clone();
    // Sanitize: use only the basename, NEVER the full stored_path (SEC-5 §2.20 requirement 1).
    let safe_filename = std::path::Path::new(&original)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("evidence_file");

    let mime = ev
        .mime_type
        .as_deref()
        .unwrap_or("application/octet-stream")
        .to_owned();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        mime.parse().unwrap_or(axum::http::header::HeaderValue::from_static(
            "application/octet-stream",
        )),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{safe_filename}\"")
            .parse()
            .unwrap(),
    );
    headers.insert(
        "X-DFARS-Hash-Verified",
        if hash_verified { "true" } else { "false" }
            .parse()
            .unwrap(),
    );

    Ok((StatusCode::OK, headers, file_bytes).into_response())
}

async fn read_and_verify_file(
    ef: &evidence_files::EvidenceFile,
) -> Result<(bool, Vec<u8>), ApiError> {
    use sha2::{Digest, Sha256};
    use std::path::Path;

    let path = Path::new(&ef.stored_path);
    if !path.exists() {
        return Err(ApiError::not_found());
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let computed = format!("{:x}", hasher.finalize());
    let hash_verified = computed.eq_ignore_ascii_case(&ef.sha256);

    Ok((hash_verified, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_json_depth_within_limit() {
        let json = b"{\"a\": {\"b\": {\"c\": 1}}}";
        assert!(check_json_depth(json, 32));
    }

    #[test]
    fn check_json_depth_exceeds_limit() {
        // Build 35-level nesting
        let mut s = String::new();
        for _ in 0..35 { s.push_str("{\"a\":"); }
        s.push('1');
        for _ in 0..35 { s.push('}'); }
        assert!(!check_json_depth(s.as_bytes(), 32));
    }

    #[test]
    fn check_json_depth_handles_strings_with_braces() {
        // Braces inside strings must not count as nesting
        let json = br#"{"key": "value with { and } chars"}"#;
        assert!(check_json_depth(json, 5));
    }

    #[test]
    fn api_error_unauthorized_shape() {
        let e = ApiError::unauthorized();
        assert_eq!(e.code, "UNAUTHORIZED");
        assert_eq!(e.error, "Unauthorized");
    }

    #[test]
    fn api_error_from_apperror_sqlx_is_internal() {
        let ae = ApiError::from(AppError::Db("table not found".into()));
        assert_eq!(ae.code, "INTERNAL_ERROR");
        // Must NOT leak the sqlx message.
        assert!(!ae.error.contains("table"));
    }

    #[test]
    fn api_error_from_validation_exposes_message() {
        let ae = ApiError::from(AppError::ValidationError {
            field: "case_id".into(),
            message: "must not be empty".into(),
        });
        assert_eq!(ae.code, "VALIDATION_ERROR");
        assert!(ae.error.contains("must not be empty"));
    }
}
