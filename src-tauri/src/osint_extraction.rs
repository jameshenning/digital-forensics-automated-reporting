//! OSINT output parsing → typed DiscoveredIdentifier list.
//!
//! After Agent Zero returns per-tool `raw_output_truncated`, this module parses
//! the output per tool and produces a `Vec<DiscoveredIdentifier>`. The Rust
//! side then dedupes that list against the entity's existing active rows in
//! `business_identifiers` / `person_identifiers` and inserts any new ones
//! with a `notes = "Auto-discovered via OSINT <tool> on <iso_date>"` stamp so
//! provenance is preserved and the investigator can still edit or delete them.
//!
//! The parsers are deliberately conservative: we only keep values that match
//! the strict regex for the declared kind, and we skip any value that starts
//! with `-` (argv-injection safety, mirrors `validate_input` in the
//! `*_identifiers` modules). Unknown tools or unparseable output return an
//! empty vec rather than erroring — this is best-effort enrichment, never a
//! reason to fail the whole OSINT run.

use regex::Regex;
use serde::{Deserialize, Serialize};

// ─── Public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredIdentifier {
    /// Must match a valid kind for the target entity type.
    /// Business: domain | registration | ein | email | phone | address | social | url
    /// Person:   email | username | handle | phone | url
    pub kind: String,
    pub value: String,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Person,
    Business,
}

// ─── Public entry point ──────────────────────────────────────────────────────

/// Parse an OSINT tool's raw output into a list of discovered identifiers
/// typed for the target entity kind. Unknown tools return an empty vec.
///
/// `tool_name` is matched case-insensitively. Version suffixes in the name
/// (e.g. `theHarvester-4.0`) are allowed — we prefix-match on the base name.
pub fn extract_from_run(
    tool_name: &str,
    raw_output: &str,
    entity_kind: EntityKind,
) -> Vec<DiscoveredIdentifier> {
    if raw_output.trim().is_empty() {
        return Vec::new();
    }
    let t = tool_name.to_lowercase();
    // Prefix-match (tool names may carry version suffixes like "theHarvester-4.0").
    let raw = |prefix: &str| t.starts_with(prefix);

    let results = if raw("theharvester") {
        extract_theharvester(raw_output, entity_kind)
    } else if raw("spiderfoot") {
        extract_spiderfoot_csv(raw_output, entity_kind)
    } else if raw("whois") {
        match entity_kind {
            EntityKind::Business => extract_whois(raw_output),
            EntityKind::Person => Vec::new(), // whois doesn't run on persons
        }
    } else if raw("subfinder") {
        match entity_kind {
            EntityKind::Business => extract_subfinder(raw_output),
            EntityKind::Person => Vec::new(),
        }
    } else if raw("sherlock") {
        match entity_kind {
            EntityKind::Person => extract_sherlock(raw_output),
            EntityKind::Business => Vec::new(), // sherlock is person-scoped
        }
    } else if raw("holehe") {
        match entity_kind {
            EntityKind::Person => extract_holehe(raw_output),
            EntityKind::Business => Vec::new(),
        }
    } else if raw("onionsearch") || raw("darkdump") {
        extract_urls_generic(raw_output, entity_kind)
    } else {
        Vec::new()
    };

    // Intra-run dedupe by (kind, lowercase(value), lowercase(platform)).
    dedupe(results)
}

// ─── Per-tool extractors ─────────────────────────────────────────────────────

/// whois output — loosely structured "Key: value" lines. We extract:
///   - `Registrar: ...`  → kind=registration, platform="registrar"
///   - `Registrant Name: ...` etc. are PII and intentionally skipped.
///
/// We do NOT re-extract the queried domain (caller already has it).
fn extract_whois(output: &str) -> Vec<DiscoveredIdentifier> {
    let mut out = Vec::new();
    for line in output.lines() {
        let Some((raw_key, raw_val)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key.trim().to_lowercase();
        let val = raw_val.trim();
        if val.is_empty() || starts_with_dash(val) {
            continue;
        }
        if key == "registrar" || key == "sponsoring registrar" {
            out.push(DiscoveredIdentifier {
                kind: "registration".to_string(),
                value: val.to_string(),
                platform: Some("registrar".to_string()),
            });
        }
    }
    out
}

/// subfinder — one subdomain per non-empty, non-comment line.
fn extract_subfinder(output: &str) -> Vec<DiscoveredIdentifier> {
    let mut out = Vec::new();
    for raw in output.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('[') || line.starts_with('#') {
            continue;
        }
        if is_domain_like(line) && !starts_with_dash(line) {
            out.push(DiscoveredIdentifier {
                kind: "domain".to_string(),
                value: line.to_lowercase(),
                platform: None,
            });
        }
    }
    out
}

/// theHarvester — produces lines with emails and hosts. We extract:
///   - emails via strict regex
///   - hostnames from "Hosts found:" sections and general domain matches
///
/// The frontend-reported entity kind drives whether we keep the domain-kind
/// results (businesses) or drop them (persons don't have a `domain` kind).
fn extract_theharvester(output: &str, entity: EntityKind) -> Vec<DiscoveredIdentifier> {
    let mut out = Vec::new();
    for email in find_emails(output) {
        out.push(DiscoveredIdentifier {
            kind: "email".to_string(),
            value: email,
            platform: None,
        });
    }
    if matches!(entity, EntityKind::Business) {
        for d in find_domains(output) {
            out.push(DiscoveredIdentifier {
                kind: "domain".to_string(),
                value: d,
                platform: None,
            });
        }
    }
    out
}

/// spiderfoot CSV — when run with `-o csv` the output is
///   "Updated","Type","Module","Source","F/P","Data"
/// (header row first). We map `Type` → our identifier kinds. Rows whose type
/// maps to a kind the target entity supports are kept; others dropped.
fn extract_spiderfoot_csv(output: &str, entity: EntityKind) -> Vec<DiscoveredIdentifier> {
    let mut out = Vec::new();
    for (idx, raw) in output.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let cols = parse_csv_row(line);
        if cols.len() < 6 {
            continue;
        }
        // Skip header.
        if idx == 0 && cols[0].eq_ignore_ascii_case("updated") {
            continue;
        }
        let sf_type = cols[1].trim();
        let module = cols[2].trim();
        let data = cols[5].trim().trim_matches('"').trim();
        if data.is_empty() || starts_with_dash(data) {
            continue;
        }
        if let Some((kind, normalized)) = map_spiderfoot_type(sf_type, data, entity) {
            out.push(DiscoveredIdentifier {
                kind: kind.to_string(),
                value: normalized,
                platform: if module.is_empty() {
                    None
                } else {
                    Some(module.to_string())
                },
            });
        }
    }
    out
}

/// sherlock — "[+] <platform>: <url>" lines indicate a confirmed account.
/// We extract both the URL (kind=url) and, if we can parse a username from
/// the URL path, a handle (kind=handle, platform=<platform>).
fn extract_sherlock(output: &str) -> Vec<DiscoveredIdentifier> {
    let mut out = Vec::new();
    for raw in output.lines() {
        let line = raw.trim();
        // Sherlock success markers: "[+] SiteName: https://..."
        let Some(rest) = line.strip_prefix("[+]").map(str::trim) else {
            continue;
        };
        let Some((site, rest)) = rest.split_once(':') else {
            continue;
        };
        let site = site.trim();
        let rest = rest.trim();
        // The rest of the line is usually the URL, sometimes with trailing text.
        let url = rest.split_whitespace().next().unwrap_or("").to_string();
        if url.is_empty() || starts_with_dash(&url) {
            continue;
        }
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            continue;
        }
        out.push(DiscoveredIdentifier {
            kind: "url".to_string(),
            value: url.clone(),
            platform: if site.is_empty() {
                None
            } else {
                Some(site.to_string())
            },
        });
        // Derive handle from the last non-empty path segment.
        if let Some(handle) = handle_from_url(&url) {
            if !starts_with_dash(&handle) && !site.is_empty() {
                out.push(DiscoveredIdentifier {
                    kind: "handle".to_string(),
                    value: handle,
                    platform: Some(site.to_string()),
                });
            }
        }
    }
    out
}

/// holehe — lines like "[+] twitter.com" indicate an email is registered.
/// The value reported is the email (already on the entity as the submitted
/// identifier), but recording it per-platform adds signal even when we have
/// the email itself, so we attach the platform.
fn extract_holehe(output: &str) -> Vec<DiscoveredIdentifier> {
    let mut out = Vec::new();
    // holehe reports the queried email on its first couple of lines; extract
    // any email we can find and pair it with the "[+] platform" hits below.
    let emails: Vec<String> = find_emails(output);
    if emails.is_empty() {
        return out;
    }
    let primary_email = &emails[0];

    for raw in output.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("[+]").map(str::trim) else {
            continue;
        };
        // rest should be a bare platform/domain like "twitter.com"
        let platform = rest.split_whitespace().next().unwrap_or("").to_string();
        if platform.is_empty() || starts_with_dash(&platform) {
            continue;
        }
        out.push(DiscoveredIdentifier {
            kind: "email".to_string(),
            value: primary_email.clone(),
            platform: Some(platform),
        });
    }
    out
}

/// onionsearch / darkdump — free-form output with URLs sprinkled in.
/// We pull every http(s) URL and tag them as kind=url.
fn extract_urls_generic(output: &str, _entity: EntityKind) -> Vec<DiscoveredIdentifier> {
    let mut out = Vec::new();
    for url in find_urls(output) {
        if starts_with_dash(&url) {
            continue;
        }
        out.push(DiscoveredIdentifier {
            kind: "url".to_string(),
            value: url,
            platform: None,
        });
    }
    out
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn starts_with_dash(s: &str) -> bool {
    s.trim_start().starts_with('-')
}

/// True if `s` looks like a domain name (at least one dot, two-letter-plus
/// TLD, all allowed chars).
fn is_domain_like(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || !s.contains('.') {
        return false;
    }
    // Allowed chars: letters, digits, hyphen, dot.
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return false;
    }
    // TLD check: last label must be 2+ letters.
    let last_label = s.rsplit('.').next().unwrap_or("");
    if last_label.len() < 2 || !last_label.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    true
}

/// Case-insensitive SpiderFoot type → our-kind map. Returns the target kind
/// and a normalized value. Rejects types we don't care about or kinds the
/// target entity doesn't support.
fn map_spiderfoot_type(
    sf_type: &str,
    data: &str,
    entity: EntityKind,
) -> Option<(&'static str, String)> {
    let t = sf_type.to_uppercase();
    let value = data.to_string();
    match t.as_str() {
        "EMAILADDR" | "EMAIL_ADDRESS" => Some(("email", value)),
        "DOMAIN_NAME" | "SUBDOMAIN" | "CO_HOSTED_SITE" => match entity {
            EntityKind::Business => Some(("domain", value.to_lowercase())),
            EntityKind::Person => None,
        },
        "PHONE_NUMBER" => Some(("phone", value)),
        "PHYSICAL_ADDRESS" => match entity {
            EntityKind::Business => Some(("address", value)),
            EntityKind::Person => None,
        },
        "SOCIAL_MEDIA" | "ACCOUNT_EXTERNAL_OWNED" => match entity {
            EntityKind::Business => Some(("social", value)),
            EntityKind::Person => Some(("url", value)),
        },
        "LINKED_URL_INTERNAL" | "LINKED_URL_EXTERNAL" | "URL_WEB_FRAMEWORK" => {
            Some(("url", value))
        }
        "USERNAME" => match entity {
            EntityKind::Person => Some(("username", value)),
            EntityKind::Business => None,
        },
        _ => None,
    }
}

/// Minimal CSV row parser. Handles quoted fields and escaped quotes.
/// Good enough for SpiderFoot's output — not a general CSV library.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if let Some(&'"') = chars.peek() {
                    // Escaped quote.
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            out.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    out.push(current);
    out
}

fn find_emails(text: &str) -> Vec<String> {
    // Conservative RFC-5322-subset pattern: local allows ._+-, domain labels
    // allow hyphens, TLD 2+ letters. Lowercased for dedup stability.
    let re = Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")
        .expect("email regex must compile");
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for m in re.find_iter(text) {
        seen.insert(m.as_str().to_lowercase());
    }
    seen.into_iter().collect()
}

fn find_domains(text: &str) -> Vec<String> {
    // Domain: labels of [a-z0-9-]+ separated by dots, TLD 2+ letters.
    // Conservative — does not match bare "foo" or IPs. Lowercased.
    let re = Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}\b")
        .expect("domain regex must compile");
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for m in re.find_iter(text) {
        let v = m.as_str().to_lowercase();
        // Skip obvious noise: file extensions, dotted versions.
        if v.ends_with(".exe") || v.ends_with(".dll") || v.ends_with(".so") {
            continue;
        }
        // Skip version strings like "1.2.3" — need at least one non-digit label.
        if v.split('.').all(|lbl| lbl.chars().all(|c| c.is_ascii_digit())) {
            continue;
        }
        seen.insert(v);
    }
    seen.into_iter().collect()
}

fn find_urls(text: &str) -> Vec<String> {
    let re = Regex::new(r#"https?://[^\s,;'"<>`]+"#)
        .expect("url regex must compile");
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for m in re.find_iter(text) {
        let raw = m.as_str().trim_end_matches(['.', ')', ']']);
        seen.insert(raw.to_string());
    }
    seen.into_iter().collect()
}

/// Extract the trailing non-empty path segment of a URL as a candidate handle.
/// E.g. `https://twitter.com/acme_corp` → `acme_corp`.
fn handle_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let path_part = after_scheme.split_once('/')?.1;
    let last = path_part.split('/').rfind(|s| !s.is_empty())?;
    // Strip query/fragment.
    let cleaned = last.split(['?', '#']).next()?.trim();
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned.to_string())
}

fn dedupe(items: Vec<DiscoveredIdentifier>) -> Vec<DiscoveredIdentifier> {
    let mut seen: std::collections::BTreeSet<(String, String, String)> =
        std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let key = (
            item.kind.clone(),
            item.value.trim().to_lowercase(),
            item.platform
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_lowercase(),
        );
        if seen.insert(key) {
            out.push(item);
        }
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_output_returns_empty() {
        let r = extract_from_run("whois", "", EntityKind::Business);
        assert!(r.is_empty());
        let r = extract_from_run("theHarvester", "   \n\n", EntityKind::Business);
        assert!(r.is_empty());
    }

    #[test]
    fn unknown_tool_returns_empty() {
        let r = extract_from_run("not_a_real_tool", "info@acme.com", EntityKind::Business);
        assert!(r.is_empty());
    }

    #[test]
    fn whois_extracts_registrar_only() {
        let out = "Domain Name: acme.com\nRegistrar: GoDaddy.com, LLC\nRegistrant Name: Secret Person\n";
        let r = extract_from_run("whois", out, EntityKind::Business);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, "registration");
        assert_eq!(r[0].value, "GoDaddy.com, LLC");
        assert_eq!(r[0].platform.as_deref(), Some("registrar"));
    }

    #[test]
    fn whois_on_person_returns_empty() {
        let out = "Registrar: GoDaddy.com, LLC";
        let r = extract_from_run("whois", out, EntityKind::Person);
        assert!(r.is_empty());
    }

    #[test]
    fn subfinder_extracts_subdomains() {
        let out = "www.acme.com\nmail.acme.com\ndev.acme.com\n";
        let r = extract_from_run("subfinder", out, EntityKind::Business);
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|d| d.kind == "domain"));
    }

    #[test]
    fn subfinder_skips_bracket_lines_and_non_domains() {
        let out = "[INF] subfinder v2.6.0\nwww.acme.com\nnot a domain\n#comment\n";
        let r = extract_from_run("subfinder", out, EntityKind::Business);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].value, "www.acme.com");
    }

    #[test]
    fn theharvester_extracts_emails_and_domains() {
        let out = "Emails found:\ninfo@acme.com\nadmin@acme.com\nHosts found:\nmail.acme.com\napi.acme.com\n";
        let r = extract_from_run("theHarvester", out, EntityKind::Business);
        let kinds: Vec<&str> = r.iter().map(|d| d.kind.as_str()).collect();
        assert!(kinds.contains(&"email"));
        assert!(kinds.contains(&"domain"));
    }

    #[test]
    fn theharvester_on_person_drops_domains() {
        let out = "info@acme.com\nmail.acme.com";
        let r = extract_from_run("theHarvester", out, EntityKind::Person);
        assert!(r.iter().all(|d| d.kind == "email"));
    }

    #[test]
    fn spiderfoot_csv_parsing() {
        let out = concat!(
            "Updated,Type,Module,Source,F/P,Data\n",
            "2026-04-16,EMAILADDR,sfp_email,acme.com,0,info@acme.com\n",
            "2026-04-16,DOMAIN_NAME,sfp_dnsresolve,acme.com,0,mail.acme.com\n",
            "2026-04-16,PHYSICAL_ADDRESS,sfp_company,acme.com,0,\"123 Main St, Wilmington DE\"\n",
        );
        let r = extract_from_run("spiderfoot", out, EntityKind::Business);
        assert_eq!(r.len(), 3);
        let by_kind: std::collections::HashMap<String, String> =
            r.iter().map(|d| (d.kind.clone(), d.value.clone())).collect();
        assert_eq!(by_kind.get("email").map(|s| s.as_str()), Some("info@acme.com"));
        assert_eq!(by_kind.get("domain").map(|s| s.as_str()), Some("mail.acme.com"));
        assert_eq!(
            by_kind.get("address").map(|s| s.as_str()),
            Some("123 Main St, Wilmington DE")
        );
    }

    #[test]
    fn spiderfoot_drops_unsupported_kinds_for_person() {
        let out = concat!(
            "Updated,Type,Module,Source,F/P,Data\n",
            "2026-04-16,PHYSICAL_ADDRESS,sfp_company,x,0,123 Main St\n",
            "2026-04-16,USERNAME,sfp_account,x,0,acme_corp\n",
        );
        let r = extract_from_run("spiderfoot", out, EntityKind::Person);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, "username");
    }

    #[test]
    fn sherlock_extracts_url_and_handle() {
        let out = "[+] Twitter: https://twitter.com/acme_corp\n[+] GitHub: https://github.com/acme\n[-] NotFound: https://example.com/notreal\n";
        let r = extract_from_run("sherlock", out, EntityKind::Person);
        let urls: Vec<&str> = r
            .iter()
            .filter(|d| d.kind == "url")
            .map(|d| d.value.as_str())
            .collect();
        let handles: Vec<&str> = r
            .iter()
            .filter(|d| d.kind == "handle")
            .map(|d| d.value.as_str())
            .collect();
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://twitter.com/acme_corp"));
        assert!(handles.contains(&"acme_corp"));
    }

    #[test]
    fn holehe_pairs_email_with_platforms() {
        let out = "Target: user@acme.com\n[+] twitter.com\n[+] github.com\n";
        let r = extract_from_run("holehe", out, EntityKind::Person);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|d| d.kind == "email" && d.value == "user@acme.com"));
        let platforms: Vec<String> = r
            .iter()
            .filter_map(|d| d.platform.clone())
            .collect();
        assert!(platforms.contains(&"twitter.com".to_string()));
        assert!(platforms.contains(&"github.com".to_string()));
    }

    #[test]
    fn onionsearch_extracts_onion_urls() {
        let out = "Hit: http://abcd1234.onion/page\nMiss\nAnother: https://xyz.onion/home.\n";
        let r = extract_from_run("onionsearch", out, EntityKind::Business);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|d| d.kind == "url"));
    }

    #[test]
    fn dash_prefixed_values_are_rejected() {
        // Construct a theHarvester-style output with a hostile domain.
        let out = "emails found:\ninfo@acme.com\nhosts:\n-maliciousflag\n";
        let r = extract_from_run("theHarvester", out, EntityKind::Business);
        // Only the email should come through; "-maliciousflag" rejected.
        assert!(r.iter().all(|d| !d.value.starts_with('-')));
    }

    #[test]
    fn intra_run_dedupe() {
        // Same email appearing twice in theHarvester output should yield one.
        let out = "info@acme.com\ninfo@acme.com\nINFO@ACME.COM\n";
        let r = extract_from_run("theHarvester", out, EntityKind::Business);
        let emails: Vec<_> = r.iter().filter(|d| d.kind == "email").collect();
        assert_eq!(emails.len(), 1);
    }

    #[test]
    fn domain_extractor_skips_version_strings() {
        // "1.2.3" should not become a domain.
        let found = find_domains("subfinder v2.6.0 running against acme.com\n");
        assert!(!found.contains(&"2.6.0".to_string()));
        assert!(found.contains(&"acme.com".to_string()));
    }

    #[test]
    fn url_extractor_strips_trailing_punctuation() {
        let urls = find_urls("See https://acme.com/page. And https://acme.com/other].");
        assert!(urls.contains(&"https://acme.com/page".to_string()));
        assert!(urls.contains(&"https://acme.com/other".to_string()));
    }

    #[test]
    fn tool_name_is_prefix_matched_case_insensitive() {
        // Mixed-case name with a version suffix still dispatches to the
        // theHarvester extractor. Person kind drops domains, leaving just email.
        let out = "info@acme.com";
        let r = extract_from_run("theHarvester-4.0.0", out, EntityKind::Person);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, "email");
    }
}
