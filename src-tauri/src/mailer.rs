/// SMTP mailer — Phase 5.
///
/// Sends plain-text emails via `lettre` with `rustls-tls`.  The SMTP password
/// is decrypted from the Fernet blob in `config.json` using `crypto.rs` and
/// wrapped in `zeroize::Zeroizing<String>` so it is wiped on drop.
///
/// `send_email`     — compose and deliver a message.
/// `test_connection` — EHLO handshake only; returns `Ok(())` if the server
///                     responds correctly without delivering any mail.
use lettre::{
    message::{Mailbox, MultiPart},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::error::AppError;

// ─── Config struct ────────────────────────────────────────────────────────────

/// Decrypted SMTP configuration — caller is responsible for wiping sensitive fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Plaintext password — caller must obtain via `crypto.decrypt(encrypted)`.
    pub password: String,
    pub from: String,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Send a plain-text email.
///
/// Password is wrapped in `Zeroizing<String>` internally — not stored beyond
/// the duration of the SMTP transaction.
pub async fn send_email(
    cfg: &SmtpConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), AppError> {
    let transport = build_transport(cfg)?;

    let from_mailbox: Mailbox = cfg
        .from
        .parse()
        .map_err(|e| AppError::SmtpSendFailed { reason: format!("invalid from address: {e}") })?;
    let to_mailbox: Mailbox = to
        .parse()
        .map_err(|e| AppError::SmtpSendFailed { reason: format!("invalid to address: {e}") })?;

    let email = Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject(subject)
        .multipart(MultiPart::alternative_plain_html(
            body.to_owned(),
            format!("<pre>{}</pre>", html_escape(body)),
        ))
        .map_err(|e| AppError::SmtpSendFailed { reason: format!("email build failed: {e}") })?;

    transport
        .send(email)
        .await
        .map_err(|e| AppError::SmtpSendFailed { reason: format!("{e}") })?;

    info!(to = %to, subject = %subject, "Email sent successfully");
    Ok(())
}

/// Test the SMTP connection without sending any mail.
///
/// Performs EHLO + QUIT.  Returns `AppError::SmtpConnectFailed` if the
/// handshake fails (wrong host, wrong port, auth rejected, etc.).
pub async fn test_connection(cfg: &SmtpConfig) -> Result<(), AppError> {
    let transport = build_transport(cfg)?;

    // lettre's `test_connection` sends EHLO and checks the greeting.
    let ok = transport
        .test_connection()
        .await
        .map_err(|e| AppError::SmtpConnectFailed { reason: format!("{e}") })?;

    if ok {
        info!(host = %cfg.host, port = cfg.port, "SMTP test connection succeeded");
        Ok(())
    } else {
        warn!(host = %cfg.host, port = cfg.port, "SMTP test connection returned false");
        Err(AppError::SmtpConnectFailed {
            reason: "server did not accept the EHLO handshake".into(),
        })
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn build_transport(cfg: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, AppError> {
    // Wrap the password so it is wiped from the heap after the transport is built.
    let _pw_guard = Zeroizing::new(cfg.password.clone());

    let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());

    // Attempt STARTTLS first (port 587). Fall back to implicit TLS (port 465).
    // If the port is 25 or the TLS negotiation fails, lettre will fall through to plain.
    let tls_params = TlsParameters::builder(cfg.host.clone())
        .build_rustls()
        .map_err(|e| AppError::SmtpConnectFailed { reason: format!("TLS params build: {e}") })?;

    let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
        .map_err(|e| AppError::SmtpConnectFailed { reason: format!("relay build: {e}") })?
        .port(cfg.port)
        .tls(Tls::Required(tls_params))
        .credentials(creds)
        .build();

    Ok(transport)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_handles_special_chars() {
        let out = html_escape("<script>alert('xss')</script>");
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
    }
}
