/// TOTP (Time-Based One-Time Password) support.
///
/// Parameters must match v1's pyotp defaults exactly:
///   - Algorithm: SHA-1
///   - Digits:    6
///   - Step:      30 seconds
///   - Skew:      1 window (accepts ±1 period for clock drift, same as pyotp's valid_window=1)
///
/// Secrets are plain Base32 strings (32 chars, 160 bits) — the same format
/// pyotp.random_base32() produces.  After Fernet-decrypting the stored secret,
/// the plaintext Base32 string is passed directly to totp-rs.
///
/// SEC-1 §2.2: skew=1 is mandatory — do not leave at default.
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::AppError;

const TOTP_ISSUER: &str = "DFARS Desktop";
const DIGITS: usize = 6;
const STEP: u64 = 30;
const SKEW: u8 = 1;

fn make_totp(secret_b32: &str) -> Result<TOTP, AppError> {
    // totp-rs requires the decoded bytes when constructing via Secret::Raw.
    // We receive a Base32 string, so decode it first.
    // RFC 4648 Base32 without padding, uppercase — what pyotp produces.
    let secret = Secret::Encoded(secret_b32.to_uppercase())
        .to_bytes()
        .map_err(|e| AppError::Crypto(format!("invalid TOTP Base32 secret: {e}")))?;

    // totp-rs 5.x TOTP::new(algorithm, digits, skew, step, secret, issuer, account_name)
    TOTP::new(Algorithm::SHA1, DIGITS, SKEW, STEP, secret, None, String::new())
        .map_err(|e| AppError::Internal(format!("TOTP construction failed: {e}")))
}

/// Verify a 6-digit TOTP code against the given Base32 secret.
///
/// Strips non-digit characters first (users may type spaces between digits).
/// Returns `false` instead of an error if the secret is malformed — callers
/// should then fall through to recovery codes.
pub fn verify_code(secret_b32: &str, code: &str) -> bool {
    let cleaned: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() != DIGITS {
        return false;
    }
    match make_totp(secret_b32) {
        Ok(totp) => totp.check_current(&cleaned).unwrap_or(false),
        Err(_) => false,
    }
}

/// Build the `otpauth://` provisioning URI used by authenticator apps.
pub fn generate_provisioning_uri(secret_b32: &str, username: &str, issuer: &str) -> Result<String, AppError> {
    // Build TOTP with issuer and account_name so get_url() includes them.
    let secret = Secret::Encoded(secret_b32.to_uppercase())
        .to_bytes()
        .map_err(|e| AppError::Crypto(format!("invalid TOTP Base32 secret: {e}")))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP,
        secret,
        Some(issuer.to_owned()),
        username.to_owned(),
    )
    .map_err(|e| AppError::Internal(format!("TOTP construction failed: {e}")))?;

    Ok(totp.get_url())
}

/// Generate a new random Base32 secret suitable for TOTP enrollment.
/// Returns a 32-character uppercase Base32 string (160 bits), matching
/// the output of `pyotp.random_base32()`.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 20]; // 160 bits = pyotp default
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Encode as RFC 4648 Base32 without padding.
    data_encoding::BASE32.encode(&bytes)
}

/// Convenience: build the provisioning URI with the standard app issuer.
pub fn enrollment_uri(secret_b32: &str, username: &str) -> Result<String, AppError> {
    generate_provisioning_uri(secret_b32, username, TOTP_ISSUER)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-1 §6.5: verify that our implementation matches RFC 6238 test vectors.
    ///
    /// RFC 6238 Appendix B uses the Base32 encoding of the ASCII string
    /// "12345678901234567890" for the SHA-1 test vector.
    /// Reference values from RFC 6238, Table 1 (SHA-1 column).
    #[test]
    fn rfc6238_test_vectors_sha1() {
        // The RFC 6238 SHA-1 test secret in ASCII → Base32.
        // "12345678901234567890" as Base32 = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        let secret_bytes = data_encoding::BASE32
            .decode(secret_b32.as_bytes())
            .expect("known valid Base32");

        // Build TOTP with skew=0 so we can test exact timestamps without window wobble.
        let totp = TOTP::new(Algorithm::SHA1, 8, 0, 30, secret_bytes, None, String::new())
            .expect("RFC test vector TOTP");

        // RFC 6238 vectors for SHA-1, 8-digit, step=30:
        // T=59:      94287082
        // T=1111111109: 07081804
        // T=1111111111: 14050471
        // T=1234567890: 89005924
        // T=2000000000: 69279037
        // T=20000000000: 65353130

        let check = |t: u64, expected: &str| {
            let code = totp.generate(t);
            assert_eq!(code, expected, "RFC 6238 vector at T={t}");
        };
        check(59, "94287082");
        check(1_111_111_109, "07081804");
        check(1_111_111_111, "14050471");
        check(1_234_567_890, "89005924");
        check(2_000_000_000, "69279037");
        check(20_000_000_000, "65353130");
    }

    /// A 6-digit secret generated by our module must be verifiable immediately.
    #[test]
    fn generated_secret_verifiable() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 32, "pyotp.random_base32() produces 32 chars");
        // Generate the current code and verify it.
        let totp = make_totp(&secret).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_code(&secret, &code));
    }

    #[test]
    fn wrong_code_rejected() {
        let secret = generate_secret();
        assert!(!verify_code(&secret, "000000"));
    }

    #[test]
    fn non_digit_stripped_before_verify() {
        let secret = generate_secret();
        let totp = make_totp(&secret).unwrap();
        let code = totp.generate_current().unwrap();
        // Insert spaces (as a user might) — should still verify.
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(verify_code(&secret, &spaced));
    }
}
