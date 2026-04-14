# SEC-4/5: Network Security Review — Agent Zero Client + axum External REST API
**DFARS Desktop v2 — Pre-Implementation Security Gate**
**Reviewer:** security-compliance-auditor
**Date:** 2026-04-12
**Status:** APPROVED WITH CONDITIONS
**Phase 5 implementation:** BLOCKED pending resolution of MUST-DO items 1–5. All other Phase 5 work (drives, AI command wiring, settings screens) may proceed in parallel.

---

## 1. Executive Summary

The v1 REST API and Agent Zero client are well-structured for their threat model: bearer token auth, append-only evidentiary routes, and a clean separation between the internal session-gated surface and the external bearer surface. The v2 design inherits these strengths and the Phase 1 `auth::tokens::verify` implementation (with `token_preview` fast path and Argon2 verification) is the correct foundation for the axum middleware.

Three concerns require MUST-DO resolution before code is written. First, the `token_preview` fast-path reveals a timing channel: a caller without a matching `token_preview` gets a fast reject in ~microseconds while a caller with a matching preview pays the Argon2 cost (~100ms). This is a timing oracle distinguishing "preview match" from "no preview match" — a modest concern against a local threat model but worth closing cheaply. Second, `bind_host = "0.0.0.0"` exposes the axum server to the entire local network without any secondary opt-in gate or UI warning — anyone on the same WiFi segment can reach a surface that mutates chain-of-custody records. Third, `agent_zero_url` in `config.json` is freeform: if the value is tampered (malware modifying config.json or social engineering), DFARS will exfiltrate the complete case payload — including investigator narratives, custody chains, and hashes — to an attacker-controlled server on the next `ai_summarize_case` call.

Five additional MUST-DO items cover request body size limits (OOM prevention), error response sanitization, token-space isolation between session auth and bearer auth, audit actor format, and serde_json depth limit. The outbound `analyze_evidence` / `forensic_analyze` paths each have a 180s and 300s timeout respectively that are not mentioned in the spec — these must be explicitly carried into v2 and reflected in the agent_zero.rs design.

**Verdict: APPROVED WITH CONDITIONS.** axum routes and agent_zero.rs are unblocked after MUST-DO items 1–8 are resolved and reflected in the implementation design. No issues found that preclude Phase 5 from starting once the design is locked.

---

## 2. Findings by Area

### 2.1 SEC-4 — Crate Choices (axum, reqwest)

**axum 0.7 / 0.8:**
axum 0.7.x is stable and widely deployed against tokio 1.x / tower / hyper 1.x. As of April 2026 there are no known CVEs in axum 0.7.x that affect a loopback-only server. axum 0.8 reached stable in early 2026 with an improved `Router::with_state` ergonomic — either is acceptable; 0.7 is the safer migration target since it is already battle-tested in production use. Recommend 0.7 for Phase 5; plan upgrade to 0.8 in Phase 7 cleanup if ecosystem alignment is complete by then.

**reqwest 0.12 with rustls:**
reqwest 0.12 with `rustls-tls` (not `native-tls`) is the correct choice. It eliminates the OpenSSL dependency, matches the rustls already in sqlx's dependency tree, and compiles cleanly on Windows MSVC. No known CVEs in reqwest 0.12.x as of this review. Confirm that the `Cargo.toml` feature flags are `default-features = false, features = ["rustls-tls", "json", "stream"]` to avoid pulling in the default `native-tls` or `openssl` features.

**tower-http:**
tower-http is the natural companion for axum middleware (request size limits, logging, compression). Use `tower_http::limit::RequestBodyLimitLayer` for body size enforcement (MUST-DO 4).

**Verdict: APPROVED.** reqwest 0.12 + rustls + axum 0.7 is correct. Lock crate versions in `Cargo.lock` and audit before Phase 5 merges.

---

### 2.2 SEC-4 — Agent Zero Client TLS (Outbound)

**Current v1 behavior:** `agent_zero_client._post()` uses `urllib.request.urlopen` with no TLS — the URL is `http://host.docker.internal:50080`. Bytes transit the loopback stack inside the Windows host; they do not traverse any physical network interface. The Docker virtual ethernet adapter (`vEthernet (WSL)` or similar) routes between host and container entirely in kernel memory.

**Risk analysis:** Plain HTTP is acceptable here. The traffic never leaves the physical host. An attacker who can sniff the Docker virtual ethernet adapter already has OS-level access (outside this threat model). Forcing HTTPS for Docker loopback adds cert management burden with no realistic attacker that benefits.

**However:** The `agent_zero_url` field in `config.json` accepts any string. If it is changed to `https://external-server.com`, reqwest will follow it over TLS — so the URL validation (MUST-DO 6) is the actual protection, not TLS enforcement.

**Verdict:** Plain HTTP for local Docker is acceptable. The mitigating control is URL allowlist validation, not TLS. Document this explicitly in agent_zero.rs as a comment.

---

### 2.3 SEC-4 — Agent Zero URL Validation (Outbound — MUST-DO)

**Finding:** `config.json` stores `agent_zero_url` as freeform user input. v1's `_load_settings()` does no URL validation before constructing `full_url = url + path` and dispatching the request. The reqwest client in v2 would inherit this behavior.

**Exploit scenario:** An attacker with write access to `%APPDATA%\DFARS\config.json` (malware, or a privilege escalation chain) changes `agent_zero_url` to `https://attacker.example.com`. The next time the investigator calls `ai_summarize_case`, DFARS constructs the full case payload — all evidence descriptions, custody chains, SHA-256 hashes, tool usage records, analysis notes, and investigator narrative — and POSTs it to the attacker's server over HTTPS (with valid TLS, fully encrypted, authenticated by the attacker's own cert). The investigator sees a normal response because the attacker's server proxies the call or returns a plausible fake.

This is the highest-risk exfiltration path in the entire Phase 5 surface.

**Remediation (MUST-DO 6):** In `agent_zero.rs`, validate `agent_zero_url` before use:

```
Allowlist (exact scheme + host, any port):
  http://localhost
  http://127.0.0.1
  http://host.docker.internal

Reject anything else UNLESS `config.json` also contains:
  allow_custom_agent_zero_url = true
  AND the settings UI has shown and logged a warning banner.
```

Implementation steps:
1. Parse the URL with the `url` crate (already a reqwest transitive dependency).
2. Check `scheme == "http"` and `host` is one of `localhost`, `127.0.0.1`, `host.docker.internal`. If host matches, accept any port.
3. If the host fails the allowlist check, check `config.json.allow_custom_agent_zero_url`. If false or absent, return `AppError::Config("Agent Zero URL must point to localhost, 127.0.0.1, or host.docker.internal. Set allow_custom_agent_zero_url = true in settings to override.")`.
4. If `allow_custom_agent_zero_url = true`, log at WARN: `"Agent Zero URL points to non-standard host {host} — custom URL override is active"`. Write an audit entry for this condition at startup and on each settings change.
5. The settings UI must display a prominent yellow/amber banner when `allow_custom_agent_zero_url` is true.

---

### 2.4 SEC-4 — Agent Zero API Key Memory Handling

**Current v1 behavior:** `_load_settings()` decrypts the API key on every call to `_post()` (i.e., on every Agent Zero request). The key is a Python `str` and lives in memory for the duration of the function. Python's GC does not guarantee wiping string memory.

**v2 analysis:** `crypto.rs`'s `decrypt()` returns `Vec<u8>`, from which the caller will decode a UTF-8 string. The current `agent_zero.rs` skeleton (not yet written) will need to do this. If the decrypted key is stored as a plain `String`, it lives in heap memory until the allocator reclaims it — it is not guaranteed to be zeroed.

**Threat model context:** The memory-sniffing attack (scanning process heap for the plaintext key) requires OS-level access, which is outside this threat model. Nonetheless, `zeroize::Zeroizing<String>` is a two-line change that closes the gap.

**Recommendation (SHOULD-DO 3):** Wrap decrypted API key in `Zeroizing<String>`. In the `reqwest::Client` builder, use the key from `Zeroizing<String>` to construct the `Authorization` header value (as `HeaderValue::from_str(&*key)?`), then let the `Zeroizing` wrapper wipe the heap allocation when it drops out of scope.

**Verdict:** PASS. Zeroize is a proportional hardening for this threat model. Mark SHOULD-DO, not MUST-DO.

---

### 2.5 SEC-4 — Agent Zero Response Body Size Limits (MUST-DO)

**Finding:** v1's `urllib.request.urlopen` reads the entire response body via `resp.read()` with no size cap. A buggy or malicious Agent Zero response of unbounded size would be read entirely into memory, potentially OOM-ing the process.

**v2 concern:** reqwest 0.12 also reads response bodies without a default cap. `response.json::<T>()` deserializes the full body into `T` — no limit.

**Remediation (MUST-DO 7):** After receiving the reqwest `Response`, check `Content-Length` if present and reject anything over the per-endpoint limit before deserializing. Additionally, use `response.bytes_stream()` with a byte-count accumulator to enforce a hard cap even without `Content-Length`:

| Endpoint | Typical response | Hard cap |
|---|---|---|
| `dfars_enhance` | ~2 KB narrative | 64 KB |
| `dfars_classify` | ~1 KB JSON | 16 KB |
| `dfars_summarize` | ~10 KB markdown | 256 KB |
| `dfars_analyze_evidence` | ~10 KB markdown | 256 KB |
| `dfars_forensic_analyze` | ~50 KB structured findings | 1 MB |

Implementation: write a helper `fn bounded_body(resp: Response, max_bytes: usize) -> Result<Bytes, AppError>` that uses `resp.bytes_stream()`, accumulates bytes with a counter, and returns `AppError::PayloadTooLarge` if the counter exceeds `max_bytes`.

---

### 2.6 SEC-4 — Agent Zero Request Timeouts

**Current v1 behavior:**
- `enhance_description`, `classify_case`: 60 s (default `_post` timeout)
- `summarize_case`: 120 s
- `analyze_evidence`: 180 s
- `forensic_analyze`: 300 s (5 minutes)

**Analysis:** These timeouts are appropriate for the underlying operations (LLM inference + tool execution). The 300 s forensic_analyze timeout is the most aggressive — Agent Zero is running actual Kali Linux forensic tools (exiftool, binwalk, volatility, etc.) against potentially large evidence files. A 5-minute timeout is reasonable.

**v2 requirement:** Replicate these exact timeouts in `agent_zero.rs`. Use reqwest's `ClientBuilder::timeout()` for a per-client global timeout and override per-call via `RequestBuilder::timeout()`. Note that reqwest's `timeout()` is a total request timeout (connect + send + receive combined), so set it to the endpoint-specific values above.

**Add a separate connect timeout:** Use `ClientBuilder::connect_timeout(Duration::from_secs(10))` on the client. A 10 s connect timeout catches the case where Agent Zero container is down — the user gets a fast error rather than waiting for the full endpoint timeout.

**Verdict:** Tiered timeouts are correct. Connect timeout addition is a MUST-DO (currently absent in v1, a real user-experience gap when Agent Zero is unreachable).

---

### 2.7 SEC-4 — Data Exfiltration Surface — What Goes to Agent Zero

This is the most sensitive question in the Phase 5 scope.

**`ai_enhance(text)` → sends:** Only the investigator-typed narrative string (from UI). No case metadata, no PII beyond what the investigator manually typed. Low risk.

**`ai_classify(text)` → sends:** Same — only the investigator-typed text. Low risk.

**`ai_summarize_case(case_id)` → sends:** The FULL case payload assembled by `_full_case()` in `api_routes.py`:
- `case`: all case metadata including `investigator` (full name), `agency`, `classification`, `description`
- `evidence`: all evidence records including `description`, `collected_by`, `location`, `serial_number`
- `custody`: full custody chain with `from_party`, `to_party`, `action`, `location`, `purpose`, `notes`
- `hashes`: all hash values (`hash_value` is a SHA-256 hex string — not sensitive by itself)
- `tools`: all tool usage records
- `analysis`: all analysis notes including full `finding` and `description` text

This is the complete investigative record for the case. It may contain: real investigator names, suspect descriptions embedded in narrative fields, physical locations, device serial numbers, and the full chain of forensic possession. For a law enforcement case, this is CUI (Controlled Unclassified Information).

**`evidence_forensic_analyze(...)` → sends:** The evidence file itself (indirectly — Agent Zero downloads it via the `/download` endpoint using the API token passed in the payload). It also sends `dfars_api_token` in the request body to Agent Zero — this means the bearer token is transmitted to Agent Zero.

**Risk:** The bearer token included in the forensic_analyze payload gives Agent Zero full write access to the axum API. If Agent Zero's response handler is compromised (or if Agent Zero is pointed at a rogue URL per §2.3), the attacker has an API token that can POST to all 12 axum endpoints.

**Remediation:**

1. **MUST-DO (§MUST-DO 8):** Display a one-time warning in the UI before the first `ai_summarize_case` call: "This will send your complete case record, including investigator names, custody chains, and evidence descriptions, to your Agent Zero instance. Agent Zero may log or forward this data depending on its configuration. Continue?"

2. **SHOULD-DO:** Implement per-field opt-out: allow the user to exclude `custody`, `hashes`, or `tools` from the summary payload via a checkbox panel in the AI settings.

3. **SHOULD-DO:** Audit-log the exact field list sent in each `ai_summarize_case` call, not just "AI case summary generated."

4. **SHOULD-DO:** The `dfars_api_token` included in `forensic_analyze` payloads should be a short-lived or scoped token if possible. Alternatively, document clearly in the UI that the "forensic analyze" feature shares an API token with Agent Zero that grants full write access.

---

### 2.8 SEC-4 — Agent Zero as a Trust Boundary

**Question (Q15 from brief):** Should Agent Zero be treated as a trusted extension of the app, or as a semi-trusted external system?

**Analysis:** Agent Zero is the user's own container running on their own machine. However:
- Agent Zero itself has a plugin system that can load arbitrary Python plugins.
- The `_dfars_integration` plugin calls back into DFARS with a full API token.
- Agent Zero may be configured to use cloud LLM providers that log inference requests.

**Recommendation:** Treat Agent Zero as a **semi-trusted boundary**. It is trusted to receive case data (the user explicitly chose to use it), but it is not trusted to modify its own communication channel or to have received tamper-free instructions (Agent Zero plugins can be added by anyone with filesystem access to the container). Therefore:
- Validate all responses from Agent Zero before acting on them (do not execute any field as code or SQL; only use the narrative text fields in display contexts).
- The URL allowlist in §2.3 is the primary control.
- Do not pass more data than is necessary for each call (this is currently fine — enhance and classify send only the typed text).

---

### 2.9 SEC-5 — Bearer Token Verification in axum Middleware

**Phase 1 `auth::tokens::verify` analysis:**

The implementation in `tokens.rs` is sound. The fast-path lookup by `token_preview` (first 12 chars) then Argon2 verification is correct. Two timing-related observations:

**Observation 1 — Preview timing channel:**
- If `token_preview` does NOT match any row: DB returns empty, function returns `Ok(None)` in microseconds.
- If `token_preview` DOES match: Argon2 verify runs (~100ms), then returns.

This is a timing oracle: an external caller can learn whether their token's first 12 characters match any stored token by measuring response time. The `token_preview` is already displayed in the DFARS UI and is not secret — so the oracle does not reveal anything additional to a legitimate user. However, for a purely external caller, the oracle distinguishes "no token with this preview" from "wrong hash for this preview" without paying the full Argon2 cost.

**Threat model context:** The attacker must be able to call the axum endpoint and measure HTTP response times. Given `bind_host = 127.0.0.1`, only local processes can do this. The oracle is a low-severity timing leak in this context.

**Mitigation (MUST-DO 1):** Add a constant-time dummy Argon2 call when no row is found for the preview, so both code paths take ~100ms. Pattern: if `fetch_optional` returns `None`, call `argon::verify_secret(plaintext, &AppState::dummy_hash)` (same field used for the username enumeration guard in login), discarding the result, then return `Ok(None)`. This eliminates the microsecond-vs-100ms distinguisher.

**Observation 2 — Token revocation latency:**
The current `verify()` function always fetches from the DB with no middleware-level cache. Revocation (DELETE from `api_tokens`) takes effect on the next request to axum — no cache to flush, no grace period. This is the correct design: O(1) DB SELECT per request on a single-user tool is negligible cost, and revocation is immediate.

**Verdict for observation 2:** Correct as implemented. Document explicitly in `agent_zero.rs` and axum middleware comments that there is no token cache by design — revocation is immediate upon DB delete.

---

### 2.10 SEC-5 — Session Guard vs. Bearer Token Isolation (MUST-DO)

**Concern:** The Tauri IPC surface uses `require_session(state, session_token)` for all mutation commands. The axum surface uses `auth::tokens::verify(pool, bearer_token)`. These are structurally different:

| Property | Session token | API bearer token |
|---|---|---|
| Format | Random 32-byte opaque string | `dfars_` + base64(32 bytes) |
| Storage (app) | In-memory `HashMap<String, SessionData>` | `api_tokens` table (Argon2 hash + preview) |
| Storage (client) | React `sessionStorage` | Agent Zero `config.yaml` |
| Auth check | O(1) HashMap lookup | DB SELECT + Argon2 |
| Scope | Tauri IPC commands only | axum HTTP endpoints only |
| Prefix | None (raw random bytes) | `dfars_` |

**Isolation gap to confirm:** Could a session token accidentally authenticate an axum request? Session tokens have no `dfars_` prefix — so `tokens::verify` would return `Ok(None)` immediately (`!plaintext.starts_with(TOKEN_PREFIX)`). Could a bearer API token authenticate a `require_session` check? `require_session` looks up the token in the in-memory `SessionState` HashMap — an API bearer token would not be present there. The isolation appears structurally sound.

**But verify one edge case (MUST-DO 2):** There must be no code path where an API token is inserted into the session HashMap, or where a session token is stored in `api_tokens`. Add a compile-time comment or assertion in both `auth/session.rs` and `auth/tokens.rs` documenting the isolation invariant: "Session tokens are in-memory only. API bearer tokens are persisted. These token spaces must never intersect." Write a test that calls `require_session` with a `dfars_`-prefixed string and confirms it returns `AppError::Unauthorized`.

---

### 2.11 SEC-5 — Request Body Size Limits (MUST-DO)

**Current v1 behavior:** Flask's `request.get_json(silent=True)` imposes no body size limit. Any POST body is fully read before parsing.

**v2 axum requirement:** Use `tower_http::limit::RequestBodyLimitLayer` as a global layer on the axum router, with per-route overrides via `axum::extract::DefaultBodyLimit::max(N)`.

**Recommended limits per route:**

| Route | Method | Recommended limit | Rationale |
|---|---|---|---|
| `POST /api/v1/cases` | POST | 16 KiB | Case fields are short strings; 16 KiB is generous |
| `PATCH /api/v1/cases/:id` | PATCH | 16 KiB | Same as create |
| `POST /api/v1/cases/:id/evidence` | POST | 16 KiB | Evidence description can be verbose |
| `POST /api/v1/cases/:id/custody` | POST | 8 KiB | Short strings |
| `POST /api/v1/cases/:id/hashes` | POST | 4 KiB | Hash values + notes |
| `POST /api/v1/cases/:id/tools` | POST | 64 KiB | `command_used` can be a full CLI with long args |
| `POST /api/v1/cases/:id/analysis` | POST | 32 KiB | `description` and `finding` can be lengthy |
| GET routes | GET | 0 (no body) | No body expected |

**Global floor:** Set `RequestBodyLimitLayer::new(64 * 1024)` (64 KiB) as the global layer. Routes with larger limits (tools: 64 KiB, analysis: 32 KiB) are within this global cap. The tools route matches the global cap exactly; if `command_used` payloads are consistently larger in practice, the per-route override can raise it to 128 KiB. Do not set a global limit above 128 KiB.

---

### 2.12 SEC-5 — JSON Parsing Depth Limit (MUST-DO)

**Finding:** serde_json has no built-in recursion depth limit by default. A POST body containing deeply nested JSON (`{"a":{"a":{"a":...}}}` to 10,000 levels) can overflow the call stack in serde_json's recursive parser, causing a stack overflow and process crash.

**Practical attack:** The axum request body size limit (§2.11) partially mitigates this — a 64 KiB JSON body can only have ~3,200 levels of nesting if every nesting is `{"a":` (5 bytes). At default Rust stack sizes (8 MiB), 3,200 serde_json recursion levels is below the overflow threshold (~4,000–6,000 depending on the serde_json version). The body size limit is therefore a meaningful mitigation, but not a complete one.

**Remediation (MUST-DO 3):** Do not rely on the body size limit alone. Use one of:

Option A (preferred): `serde_json::from_slice` with a pre-check: count the maximum nesting depth by iterating the raw bytes and counting unescaped `{` and `[` characters. If depth > 32, reject with 400 before calling serde_json. This is O(n) in body size, cheap, and robust.

Option B: Use the `sonic-rs` or `simd-json` crate which supports bounded depth. `simd-json` has explicit depth limiting. However, adding a new JSON crate for one purpose is more complex than Option A.

Option C: Use `serde_json::Deserializer::from_slice(...).disable_recursion_limit()` — note: this REMOVES the limit, which is the wrong direction. Do not use this option.

**Recommended implementation:** Write a small helper `fn check_json_depth(bytes: &[u8], max: usize) -> bool` that counts nesting depth without parsing. Call it in the axum extractor layer before deserializing. Max depth of 32 is more than sufficient for all DFARS payloads (the deepest legitimate payload is the custody body with ~3 levels of nesting).

---

### 2.13 SEC-5 — Error Response Shape (MUST-DO)

**Current v1 behavior:** Most error returns are `jsonify(error=f"Failed to create case: {e}")` where `{e}` is the Python exception string. SQLAlchemy exceptions contain table names, column names, constraint names, and sometimes partial query fragments. These leak internal schema information to the API caller.

Example v1 leak: `"Failed to add evidence: UNIQUE constraint failed: evidence.evidence_id"` — this tells the caller the table name and the constraint structure.

**v2 axum requirement:** Map all internal errors to a sanitized public shape before responding.

**AppError → HTTP response mapping:**

```
AppError::NotFound           → 404 { "error": "Not found", "code": "NOT_FOUND" }
AppError::Unauthorized       → 401 { "error": "Unauthorized", "code": "UNAUTHORIZED" }
AppError::Conflict           → 409 { "error": "Resource already exists", "code": "CONFLICT" }
AppError::Validation(msg)    → 422 { "error": msg, "code": "VALIDATION_ERROR" }
                                   (msg is caller-provided, safe to expose)
AppError::Sqlx(_)            → 500 { "error": "Internal error", "code": "INTERNAL_ERROR" }
                                   (NO sqlx error details exposed)
AppError::Io(_)              → 500 { "error": "Internal error", "code": "INTERNAL_ERROR" }
AppError::Crypto(_)          → 500 { "error": "Internal error", "code": "INTERNAL_ERROR" }
AppError::PayloadTooLarge    → 413 { "error": "Request body too large", "code": "PAYLOAD_TOO_LARGE" }
```

The `details` field is OPTIONAL and only populated for `VALIDATION_ERROR` (where the detail is the caller-supplied field name / constraint message — never a DB error string). Do not include file paths, usernames, hash values, case IDs beyond what the caller already sent, or any Rust `{:?}` debug output.

**Internal logging:** Log the full error at `tracing::error!` level on every 5xx response so it is captured in the rolling log file. The log entry should include the request path, the error type, and the full debug representation. Never surface this to the API caller.

---

### 2.14 SEC-5 — 0.0.0.0 Binding Mode (MUST-DO)

**Concern:** When `bind_host = "0.0.0.0"`, the axum server is reachable from any device on the local network — not just the Docker container. This includes any device on the same WiFi or LAN segment. A neighbor or a coffee shop co-worker on the same network can reach the `/api/v1/*` surface. They still need a valid API bearer token to do anything useful, but the token provides full write access to evidentiary records.

**Vector:** If the API token is ever leaked (sent in a log file, visible in a network trace, captured by a packet analyzer on the LAN), anyone on the same network segment can write to chain-of-custody tables, add fake analysis notes, or create fictitious custody events.

**Remediation (MUST-DO 5):**

1. When the app parses `bind_host` at startup (or when `settings_set_agent_zero` changes it), validate that the value is either `"127.0.0.1"` or `"0.0.0.0"`. Any other value is rejected.

2. When `bind_host` is `"0.0.0.0"`:
   a. Log at WARN: `"axum server binding to 0.0.0.0 — reachable from the local network. Ensure API tokens are not exposed."`.
   b. Write an audit entry: `"API server started with non-loopback bind address 0.0.0.0"`.
   c. Require a second config key `allow_network_bind = true` to be explicitly set. If `bind_host = "0.0.0.0"` but `allow_network_bind` is absent or false, refuse to start the axum server and surface an error in the UI: "Network binding requires explicit opt-in. Set allow_network_bind = true in settings to allow remote connections."
   d. Display a persistent amber banner in the DFARS UI when the server is bound to 0.0.0.0.

3. **Do NOT force TLS for `0.0.0.0`:** A self-signed cert would require the Agent Zero container's `dfars_client.py` to accept the cert (currently uses `urllib.request` with default cert validation — would need `ssl.create_default_context()` modifications). The configuration burden outweighs the benefit for a local-only Docker setup. The UI warning + second opt-in key is the proportionate control. Document the residual risk.

---

### 2.15 SEC-5 — CORS Headers

**Current v1 behavior:** Flask's `api_bp` sets no CORS headers. The only callers are the Agent Zero Python client (which does not use a browser context and ignores CORS) and direct CLI use.

**v2 axum:** No CORS headers needed. The axum server serves a machine-to-machine REST API. It is not called from a browser context (the Tauri WebView calls Tauri IPC commands, not the axum server). Agent Zero's `urllib.request` client does not enforce CORS. Setting `Access-Control-Allow-Origin: *` would be incorrect (would enable browser-based callers from any origin if a user browses to a malicious page that makes a cross-origin fetch to `http://127.0.0.1:5099`).

**Recommendation:** Set no CORS headers. If any future consumer needs to call the axum server from a browser, that is a design change requiring a new SEC review.

---

### 2.16 SEC-5 — Rate Limiting

**Assessment:** The axum surface is consumed exclusively by the Agent Zero plugin (a single local Python process). Rate limiting is not a meaningful control in this configuration — the only "attacker" that could spam the endpoint is the Agent Zero container itself, which is under the user's control.

**However:** One scenario warrants noting. A compromised or misbehaving Agent Zero plugin (e.g., a buggy loop in `dfars_forensic_analyze.py`) could trigger rapid-fire POSTs to the analysis endpoint, creating thousands of duplicate custody or analysis records in the DB. This would not be a security compromise but would be a data integrity problem.

**Recommendation (SHOULD-DO 5):** Add a simple token-bucket rate limiter at the axum layer: no more than 30 requests per second globally (not per-token — there is only one token in practice). `tower` has a `ServiceBuilder::rate_limit()` layer that is trivial to add. A 30 req/s limit would not affect normal Agent Zero usage (which is human-paced, not automated) but would catch a runaway loop.

---

### 2.17 SEC-5 — Audit Log Actor Field

**v1 behavior:** `_api_user()` in `api_routes.py` returns `f"API:{tok.get('username', '?')}:{tok.get('name', '?')}"`. This format distinguishes API-authed events from session-authed events (`_user()` returns the plain username string).

**v2 requirement:** The audit entry `actor` column must distinguish API token actors from session actors. The v1 format is acceptable but can be improved for consistency.

**Recommended format:**
- Session actor: `user:<username>` (e.g., `user:james`)
- API token actor: `api_token:<token_name>` (e.g., `api_token:Agent Zero`)

This format is:
- Consistent prefix makes programmatic filtering trivial
- Never ambiguous (a username cannot start with `api_token:`)
- Matches the spirit of v1's `API:` prefix but is cleaner

**Implementation:** The axum middleware's `VerifiedToken` struct (returned by `auth::tokens::verify`) carries `name` and `username`. The route handlers use `format!("api_token:{}", token.name)` as the actor for all audit entries.

This is MUST-DO 8 because incorrect actor attribution in audit logs undermines the chain-of-custody audit trail — a legally significant finding for this application.

---

### 2.18 SEC-5 — Chain-of-Custody Integrity Under Compromised Token

**Question:** A compromised API token gives full write access to all 12 axum endpoints. What mitigations beyond "don't leak the token" are reasonable?

**Analysis:** For a single-user tool, layered token controls (RBAC, scoped tokens) would be enterprise-grade overkill. However, three lightweight mitigations are proportionate:

1. **Idempotency (SHOULD-DO 6):** POSTing evidence twice creates two rows. The Agent Zero plugin should be well-behaved, but a network retry on a 500 error could cause a duplicate custody or analysis record. Add an optional `Idempotency-Key` header: if the axum server sees this header and a matching value in a recent-request cache (a small in-memory `HashMap<String, Instant>` evicted after 60s), return the original 201 without re-inserting. This prevents duplicate records from retries without requiring full idempotent PUT semantics.

2. **Audit log immutability:** The append-only design of axum routes means a compromised token can add fake records but cannot delete or modify existing chain-of-custody entries. This is the correct forensic design and should be maintained. Document explicitly that DELETE operations on evidentiary records are NOT exposed via the axum surface.

3. **Token scope documentation in UI:** The API token management screen should display a clear label: "This token grants full write access to all case records. Revoke immediately if compromised." Link to the audit log filtered by `api_token:` actor.

---

### 2.19 SEC-5 — AppState Layout for axum

**Current `state.rs`:** `AppState` holds `db: AppDb`, `crypto: CryptoState`, `lockout: LockoutMap`, `sessions: SessionState`, and `dummy_hash: String`. The axum server needs the `db` pool (for `auth::tokens::verify` and all DB operations) and nothing else from AppState for authentication.

**Recommendation for axum integration:**
- Pass `Arc<AppState>` as axum state (`Router::with_state(Arc::clone(&app_state))`). Do not create a separate axum-specific state struct — the shared AppState is the single source of truth for DB pools, and axum route handlers need the same `AppDb` as Tauri commands.
- The `reqwest::Client` for Agent Zero calls should live in `AppState` as a lazily-initialized field, not constructed on every call. `reqwest::Client` is designed to be shared (it manages a connection pool internally). Add a field `agent_zero_client: tokio::sync::RwLock<Option<reqwest::Client>>` initialized on first use after `is_configured()` returns true.
- The axum server runs on a separate tokio task. It shares `Arc<AppState>` with the Tauri command handlers. No additional synchronization is needed because sqlx's `SqlitePool` is `Send + Sync`.

---

### 2.20 SEC-5 — Endpoint: Evidence File Download

**Route:** `GET /api/v1/cases/:case_id/evidence/:evidence_id/files/:file_id/download`

This endpoint is called by Agent Zero's `dfars_forensic_analyze.py` to download evidence files for tool execution. It serves the raw binary file content.

**v1 implementation review:**
```python
file_path = Path(ef.stored_path)
if not file_path.exists():
    return _err(f"File not found on disk: {ef.stored_path}", 404)
```

**v1 leak:** The 404 error includes `ef.stored_path` — the full absolute path to the evidence file on disk. This exposes the storage layout to the API caller, including whether the file is on a forensic drive (path includes drive letter and directory structure) or in `%APPDATA%`. For a single-user tool this is low risk, but it is an information leak.

**v2 requirement:**
1. When the file is not found on disk, return `{"error": "File not found", "code": "NOT_FOUND"}` — do not include the stored path.
2. After serving the file, verify the stored SHA-256 matches the on-disk file (same re-hash logic as `evidence_files_download` in the Tauri command, per SEC-3 MUST-DO 4). If the hash does not match, serve the file but include a response header `X-DFARS-Hash-Verified: false` and write an ERROR-severity audit entry. Let the Agent Zero caller decide how to handle this (it should be passed back to the investigator as a warning).
3. Use `axum::response::Response` with the appropriate `Content-Type` from `ef.mime_type`. For `application/octet-stream`, instruct the response to set `Content-Disposition: attachment; filename="<sanitized_filename>"` (use only the basename, not the full stored path).

---

## 3. MUST-DO Items

These are hard gates. Phase 5 axum and agent_zero.rs code MUST NOT be written until these design decisions are locked. Each MUST-DO that is a design decision can be resolved in this review; each one that requires implementation verification must be confirmed in the Phase 5 PR.

**MUST-DO 1 — Constant-time token verification in axum middleware.**
Add a dummy Argon2 call when `token_preview` lookup returns no matching row, so both the "no match" and "wrong hash" code paths take approximately the same time (~100ms). Use `AppState.dummy_hash` for this — the same field already serving the login enumeration guard. The call must use the same Argon2 params as real token hashing and its result must be discarded. This eliminates the preview timing oracle.

**MUST-DO 2 — Token space isolation test.**
Add a test to `auth/tokens.rs` or the integration test suite that calls the session `require_session()` helper with a `dfars_`-prefixed string and confirms it returns `AppError::Unauthorized`. Add a reciprocal test that calls `auth::tokens::verify` with a session token (random bytes without `dfars_` prefix) and confirms it returns `Ok(None)`. Document the isolation invariant in both `auth/session.rs` and `auth/tokens.rs` with a comment.

**MUST-DO 3 — JSON depth limit before serde_json deserialization.**
Implement `fn check_json_depth(bytes: &[u8], max_depth: usize) -> bool` as described in §2.12. Call it in the axum body extraction layer (or in a custom extractor) before `serde_json::from_slice`. Max depth: 32. Return HTTP 400 on depth violation. Write a test that sends `{"a":{"a":...}}` nested 33 levels deep and confirms a 400 response.

**MUST-DO 4 — Per-route request body size limits.**
Apply `DefaultBodyLimit::max(N)` per route as specified in §2.11. Set `RequestBodyLimitLayer::new(64 * 1024)` globally. Tools route gets `DefaultBodyLimit::max(64 * 1024)`. Analysis route gets `DefaultBodyLimit::max(32 * 1024)`. Cases create/patch and evidence routes get `DefaultBodyLimit::max(16 * 1024)`. Custody and hash routes get `DefaultBodyLimit::max(8 * 1024)`. Return HTTP 413 on limit violation with `{"error": "Request body too large", "code": "PAYLOAD_TOO_LARGE"}`.

**MUST-DO 5 — 0.0.0.0 binding requires explicit double opt-in.**
When `bind_host = "0.0.0.0"`, require `allow_network_bind = true` in config.json. If the second key is absent, refuse to start the axum server and return an error via the `settings_test_agent_zero` command. Log a WARN and write an audit entry when binding to 0.0.0.0. Display an amber UI banner when the server is bound to a non-loopback address. The settings UI must expose `allow_network_bind` as an explicit checkbox with a warning label.

**MUST-DO 6 — Agent Zero URL allowlist validation.**
In `agent_zero.rs`, validate `agent_zero_url` from config before constructing any reqwest URL. Accept only `http://` scheme with host in `{localhost, 127.0.0.1, host.docker.internal}`. Reject anything else unless `allow_custom_agent_zero_url = true` in config. When custom URL is active, log at WARN and write an audit entry. Settings UI must display an amber banner for custom URL mode.

**MUST-DO 7 — Agent Zero response body size limits.**
Implement `bounded_body(resp: Response, max_bytes: usize) -> Result<Bytes, AppError>` in `agent_zero.rs`. Apply per-endpoint limits as specified in §2.5. Return `AppError::PayloadTooLarge` if exceeded (maps to a user-facing error in the AI command, not a panic or OOM).

**MUST-DO 8 — Audit log actor format.**
All axum mutation routes write audit entries with actor `format!("api_token:{}", token.name)`. All Tauri session-authed commands write actor `format!("user:{}", session.username)`. This format must be consistent from the first Phase 5 commit. Write a test that confirms the actor string format for a synthetic API token-authenticated request.

---

## 4. SHOULD-DO Items

**SHOULD-DO 1 — reqwest connect timeout.**
Add `ClientBuilder::connect_timeout(Duration::from_secs(10))` when constructing the Agent Zero reqwest client. Gives a fast failure when Agent Zero container is down.

**SHOULD-DO 2 — Tiered per-endpoint timeouts.**
Use endpoint-specific timeouts in `agent_zero.rs`:
- `dfars_enhance`, `dfars_classify`: 30 s total
- `dfars_summarize`, `dfars_analyze_evidence`: 120 s total
- `dfars_forensic_analyze`: 300 s total

These differ from v1 (which used 60 s for enhance/classify). 30 s is more appropriate for single LLM inference calls; the 60 s default in v1 was the generic `_post` timeout applied uniformly.

**SHOULD-DO 3 — Zeroize decrypted API key.**
Wrap the decrypted Agent Zero API key in `Zeroizing<String>` after `crypto.decrypt()`. Ensures the heap allocation is wiped on drop.

**SHOULD-DO 4 — Pre-call consent banner for ai_summarize_case.**
Display a one-time warning in the DFARS UI (using a `shown_ai_summarize_consent` flag in config.json) before the first `ai_summarize_case` call, describing exactly what case data will be sent to Agent Zero.

**SHOULD-DO 5 — Global rate limit layer.**
Add `tower::ServiceBuilder::new().rate_limit(30, Duration::from_secs(1))` to the axum router to prevent runaway Agent Zero plugin loops from creating thousands of duplicate records.

**SHOULD-DO 6 — Idempotency-Key header support for POST routes.**
Implement a simple in-memory `HashMap<String, Instant>` (60-second TTL) in AppState. If a POST request includes `Idempotency-Key`, check the map before processing. On match, return the original 201 without re-inserting. On miss, process and store the key. Prevents duplicate records from Agent Zero retry loops.

**SHOULD-DO 7 — Sanitize the evidence file download 404 response.**
Do not include the stored file path in 404 error responses from the download endpoint (§2.20).

**SHOULD-DO 8 — Hash re-verification on evidence file download.**
Re-hash the served file on every download request and include `X-DFARS-Hash-Verified: true|false` in the response header. On false, write an ERROR audit entry. Agent Zero's `dfars_forensic_analyze.py` should be updated (separately) to check this header and surface a warning in its analysis output.

---

## 5. Open Questions

**OQ-SEC4-1 — forensic_analyze timeout in v2 scope?**
The v1 `agent_zero_client.forensic_analyze()` uses a 300 s timeout. The Phase 5 spec (§8 of the migration spec) only mentions 120 s for `ai_summarize_case`. Confirm that `evidence_forensic_analyze` (the Tauri command wrapping `forensic_analyze`) is in Phase 5 scope and that the 300 s timeout is explicitly carried into `agent_zero.rs`. If forensic_analyze is deferred to a later phase, note it explicitly.

**OQ-SEC4-2 — analyze_evidence endpoint in scope?**
v1 has both `analyze_evidence` (metadata + narrative, 180 s timeout) and `forensic_analyze` (full tool execution, 300 s). The spec §6 AI helpers list only `evidence_forensic_analyze`. Is `analyze_evidence` (metadata-only, non-tool) also in Phase 5 scope, or is it subsumed by `evidence_forensic_analyze`? This affects the agent_zero.rs surface and timeout design.

**OQ-SEC4-3 — dfars_api_token in forensic_analyze payload: acceptable?**
The `dfars_forensic_analyze.py` plugin expects `dfars_api_token` in the inbound payload so it can download evidence files from DFARS. This means the DFARS app is passing its own API token back to Agent Zero. This is the correct design (Agent Zero cannot authenticate to DFARS without a token), but it deserves an explicit decision. Is it acceptable for the Agent Zero plugin to store and use this token? The token is already stored in Agent Zero's config; passing it per-request is equivalent. Confirm this is the intended design.

**OQ-SEC5-1 — axum server port: is 5099 final?**
The spec says `127.0.0.1:5099`. v1 also uses 5099 (confirmed in Agent Zero's `dfars_client.py` `api_url` config). Is this port hardcoded or configurable? If configurable via `config.json`, the `settings_get_agent_zero` / `settings_set_agent_zero` commands must expose it. The Agent Zero plugin's `default_config.yaml` must match.

**OQ-SEC5-2 — Error `code` field: use spec §6 AppError variants or an independent set?**
The `error.rs` `AppError` enum drives IPC error codes for Tauri commands. The axum error response `code` field (used by Agent Zero to interpret failures) should either reuse the same variants or define an independent set. Reusing `AppError` variants (as string-serialized via `thiserror`) is simpler — the Agent Zero plugin already parses error strings. Confirm which approach is intended before implementing the error mapping in §2.13.

---

## 6. Sign-Off Conditions for SEC-4/5 Final Approval

The following must be true in the Phase 5 PR before SEC-4 and SEC-5 are closed:

1. `auth::tokens::verify` in `tokens.rs` performs a dummy Argon2 call (using `AppState.dummy_hash`) when `token_preview` lookup returns no row, so both code paths take approximately equal time. A unit test measures that the timing difference between "no preview match" and "wrong hash" paths is not more than one order of magnitude (pragmatic — exact constant-time Argon2 is hard to guarantee in unit tests, but the dummy call must demonstrably run).

2. A test calls `require_session()` with a `dfars_`-prefixed bearer token and confirms `AppError::Unauthorized`. A test calls `tokens::verify()` with a non-`dfars_`-prefixed string (simulating a session token) and confirms `Ok(None)`.

3. A test sends a POST body with JSON nested to 33 levels and confirms a 400 response.

4. Integration tests confirm: POST with body exceeding the per-route limit returns 413. All 12 axum endpoints are covered.

5. `agent_zero.rs` validates `agent_zero_url` against the allowlist before constructing any reqwest URL. A unit test confirms that `http://evil.example.com/...` is rejected with `AppError::Config`.

6. `agent_zero.rs` uses `bounded_body()` on all Agent Zero responses. A test with a mocked response body exceeding the per-endpoint limit confirms `AppError::PayloadTooLarge` is returned (not an OOM or panic).

7. The axum server refuses to bind to `0.0.0.0` unless `allow_network_bind = true` is present in config.json. A test confirms the server falls back to `127.0.0.1` if `bind_host = "0.0.0.0"` but `allow_network_bind` is absent.

8. All axum mutation routes write audit entries with actor in the format `api_token:<name>`. An integration test verifies the audit entry actor for a synthetic POST to `/api/v1/cases/:id/custody`.

9. Error responses from axum routes never include sqlx error strings, file paths, or Rust debug output. A test that triggers a DB error (insert into a non-existent case) confirms the response body matches `{"error": "Internal error", "code": "INTERNAL_ERROR"}` exactly.

10. The `reqwest::Client` in `agent_zero.rs` is constructed once and stored in `AppState` (or a field accessible from AppState), not constructed on every call. A code review confirms no `reqwest::Client::new()` call inside any request handler.

11. Open questions OQ-SEC4-1, OQ-SEC4-2, and OQ-SEC5-1 are answered and the answers are reflected in `agent_zero.rs` and `v2-migration-spec.md §8` before Phase 5 coding begins.

---

## Appendix: v1 Behaviors Confirmed as PASS (No Action Required)

- **Bearer token format (`dfars_` prefix + 32 random bytes URL-safe base64):** Sound. Port unchanged. `tokens.rs` already implements this correctly.
- **Append-only evidentiary routes (no DELETE/PUT on custody, hashes, evidence):** Correct forensic design. The axum surface must maintain this — expose only POST for evidentiary records, no modification or deletion. Confirmed in `api_routes.py`.
- **Token last_used_at update on each verify:** Already implemented in `tokens.rs`. Provides a useful audit signal.
- **`_json_body()` silent=True pattern (no exception on missing body):** Ported correctly by treating a missing body as `{}` and returning 422 on required field absence.
- **Case PATCH whitelist (only `case_name`, `description`, `agency`, `status`, `priority`, `classification`, dates):** Correct forensic design — `case_id` and `investigator` are immutable. Port unchanged.
- **Token verification: `token_preview` indexed lookup then Argon2:** Implemented in `tokens.rs`. Fast path is correct and already in place.
- **`whoami` endpoint:** Correct. Useful for Agent Zero integration health check. Port unchanged.
- **Evidence drive validation on case create/patch:** `validate_evidence_drive()` logic must be ported to v2 Rust equivalent. Already in scope for Phase 5.
- **`dfars_` token prefix enables GitHub secret scanning:** Port unchanged. Do not remove the prefix.
- **Audit entry on every mutating API call:** Port unchanged. All audit calls in `api_routes.py` must have v2 equivalents.
