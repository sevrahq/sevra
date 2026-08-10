//! Secret-scan preflight for `push` — the last gate before store bytes leave
//! the machine. Conservative, precise patterns only (prefixed token formats,
//! PEM headers, share links), so a hit is worth stopping a push over. Both
//! file CONTENT and file PATHS are scanned: a secret in a filename lands in
//! the hub index and the feed, not just the blob. A matched value is never
//! printed on any path; a path that itself matches is shown redacted.
//!
//! Markdown and `assets.jsonl` arrive here through [`scan_store`]. Declared
//! asset bytes use the same entry scanner from `assets.rs`, after the asset
//! transport has securely opened and verified the exact manifest bytes.

use std::sync::OnceLock;

use regex::{Regex, RegexSet};

use crate::store::Store;

/// (human kind, pattern). The pattern list is deliberately conservative:
/// every entry is a vendor-prefixed format that near-certainly identifies a
/// live credential, never a generic entropy heuristic.
const PATTERNS: &[(&str, &str)] = &[
    ("AWS access key id", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("GitHub personal access token", r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub fine-grained token", r"github_pat_[A-Za-z0-9_]{22,}"),
    ("GitHub app/OAuth token", r"gh[ousr]_[A-Za-z0-9]{36}"),
    ("Anthropic API key", r"sk-ant-[A-Za-z0-9-]{20,}"),
    ("OpenAI API key", r"sk-proj-[A-Za-z0-9_-]{20,}"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}"),
    ("Stripe live key", r"[sr]k_live_[A-Za-z0-9]{20,}"),
    (
        "private key (PEM block)",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    ),
    ("1Password share link", r"share\.1password\.com/s#"),
];

pub struct SecretHit {
    /// The file's path, redacted wherever the path itself matched — safe to
    /// print even when the secret sits in the filename.
    pub path: String,
    /// The EXACT store-relative path, unredacted — it may itself BE the
    /// secret, so it is never printed on any channel. `secrets quarantine`
    /// writes it into `.sevralocal`, which lives in the store and never
    /// uploads (the walk's dot-skip).
    pub store_path: String,
    pub kind: &'static str,
    /// True when the match is in the file's PATH rather than its content.
    pub in_path: bool,
}

struct Scanner {
    /// One compiled automaton over all patterns: a single pass per haystack.
    set: RegexSet,
    /// The same patterns individually, for redacting matched path spans.
    each: Vec<Regex>,
}

/// Token formats are ASCII. Treat adjacent ASCII identifier bytes as part of
/// the same run: a credential-shaped substring inside minified code, a hash,
/// or encoded data is not a standalone token. Delimiters such as quotes,
/// whitespace, `=`, `/`, and `:` remain valid boundaries.
fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

fn bounded_spans<'a>(regex: &'a Regex, text: &'a str, right_boundary: bool) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    regex
        .find_iter(text)
        .filter_map(|found| {
            let left_ok = found.start() == 0 || !identifier_byte(bytes[found.start() - 1]);
            let right_ok = !right_boundary
                || found.end() == bytes.len()
                || !identifier_byte(bytes[found.end()]);
            (left_ok && right_ok).then_some((found.start(), found.end()))
        })
        .collect()
}

fn right_boundary(index: usize) -> bool {
    // The share-link pattern intentionally names the stable URL prefix. The
    // share id begins immediately after `#`, so requiring a right boundary
    // there would reject every real 1Password share link.
    PATTERNS[index].0 != "1Password share link"
}

fn scanner() -> &'static Scanner {
    static SCANNER: OnceLock<Scanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let patterns: Vec<&str> = PATTERNS.iter().map(|(_, p)| *p).collect();
        Scanner {
            set: RegexSet::new(&patterns).expect("secret patterns compile"),
            each: patterns
                .iter()
                .map(|p| Regex::new(p).expect("secret patterns compile"))
                .collect(),
        }
    })
}

/// Redact every secret-format match inside `text` (each replaced with `…`).
/// For path spellings and third-party error strings that must stay printable
/// even when a secret sits inside them; text with no match passes through
/// unchanged.
pub fn redact_path(text: &str) -> String {
    let sc = scanner();
    let mut spans = Vec::new();
    for index in sc.set.matches(text) {
        spans.extend(bounded_spans(&sc.each[index], text, right_boundary(index)));
    }
    if spans.is_empty() {
        return text.to_string();
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in spans {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end) in merged {
        redacted.push_str(&text[cursor..start]);
        redacted.push('\u{2026}');
        cursor = end;
    }
    redacted.push_str(&text[cursor..]);
    redacted
}

fn matching_patterns(text: &str) -> Vec<usize> {
    let sc = scanner();
    sc.set
        .matches(text)
        .into_iter()
        .filter(|index| !bounded_spans(&sc.each[*index], text, right_boundary(*index)).is_empty())
        .collect()
}

/// Scan a store-relative path. Asset transport uses this independently of
/// content inspection so a binary or oversized asset can still be refused
/// when its filename itself carries a credential.
pub(crate) fn scan_path(path: &str) -> Vec<SecretHit> {
    let matches = matching_patterns(path);
    if matches.is_empty() {
        return Vec::new();
    }
    let shown = redact_path(path);
    matches
        .into_iter()
        .map(|index| SecretHit {
            path: shown.clone(),
            store_path: path.to_string(),
            kind: PATTERNS[index].0,
            in_path: true,
        })
        .collect()
}

/// Scan UTF-8 file bytes while reporting only the (possibly redacted) path
/// and credential kind. Matched bytes never enter a printable field.
pub(crate) fn scan_content(path: &str, content: &str) -> Vec<SecretHit> {
    let shown = redact_path(path);
    matching_patterns(content)
        .into_iter()
        .map(|index| SecretHit {
            path: shown.clone(),
            store_path: path.to_string(),
            kind: PATTERNS[index].0,
            in_path: false,
        })
        .collect()
}

/// Scan every file that would be pushed — content and path both. Hits carry
/// the (redacted) shown path and the pattern kind for printing, plus the
/// exact store path for `secrets quarantine` — never matched bytes on any
/// printable field.
pub fn scan_store(store: &Store) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    let mut check = |path: &str, content: &str| {
        hits.extend(scan_path(path));
        hits.extend(scan_content(path, content));
    };
    for file in &store.files {
        check(&file.path, &file.content);
    }
    if let Some(assets) = store.assets.as_deref() {
        check("assets.jsonl", assets);
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreFile;

    /// Fixture tokens are BUILT at runtime so no secret-shaped literal ever
    /// sits in this source file (repo scanners would rightly flag them).
    fn fake(prefix: &str, filler: &str, n: usize) -> String {
        format!("{prefix}{}", filler.repeat(n))
    }

    fn store_of(files: Vec<(&str, String)>) -> Store {
        Store {
            files: files
                .into_iter()
                .map(|(path, content)| StoreFile {
                    path: path.into(),
                    content,
                })
                .collect(),
            assets: None,
        }
    }

    fn kinds_in(text: String) -> Vec<&'static str> {
        let store = store_of(vec![("note.md", text)]);
        scan_store(&store).iter().map(|h| h.kind).collect()
    }

    #[test]
    fn each_pattern_matches_its_shape() {
        let cases: Vec<(String, &str)> = vec![
            (fake("AKIA", "A", 16), "AWS access key id"),
            (fake("ASIA", "B", 16), "AWS access key id"),
            (fake("ghp_", "a", 36), "GitHub personal access token"),
            (fake("github_pat_", "c", 22), "GitHub fine-grained token"),
            (fake("gho_", "d", 36), "GitHub app/OAuth token"),
            (fake("ghs_", "d", 36), "GitHub app/OAuth token"),
            (fake("sk-ant-", "e", 20), "Anthropic API key"),
            (fake("sk-proj-", "f", 20), "OpenAI API key"),
            (fake("xoxb-", "1", 10), "Slack token"),
            (fake("xoxp-", "2", 10), "Slack token"),
            (fake("AIza", "g", 35), "Google API key"),
            (fake("sk_live_", "h", 20), "Stripe live key"),
            (fake("rk_live_", "h", 20), "Stripe live key"),
            (
                "-----BEGIN RSA PRIVATE KEY-----".into(),
                "private key (PEM block)",
            ),
            (
                "-----BEGIN PRIVATE KEY-----".into(),
                "private key (PEM block)",
            ),
            (
                "see https://share.1password.com/s#abc".into(),
                "1Password share link",
            ),
        ];
        for (value, kind) in cases {
            let found = kinds_in(format!("credential: {value}"));
            assert!(found.contains(&kind), "{kind} not found for {value:?}");
        }
    }

    #[test]
    fn near_misses_stay_clean() {
        let cases: Vec<String> = vec![
            fake("AKIA", "A", 15),     // one char short
            fake("akia", "a", 16),     // wrong case
            fake("ghp_", "a", 35),     // one char short
            fake("ghx_", "a", 36),     // not an [ousr] variant
            fake("xoxz-", "1", 10),    // not a [baprs] variant
            fake("sk_test_", "h", 20), // test-mode key, not live
            "-----BEGIN CERTIFICATE-----".into(),
            "share-1password.com/s#x".into(), // the dot is literal
            "a plain note about AWS keys".into(),
        ];
        for value in cases {
            let found = kinds_in(format!("text {value} text"));
            assert!(found.is_empty(), "false positive on {value:?}: {found:?}");
        }
    }

    #[test]
    fn credential_shapes_inside_longer_identifier_runs_stay_clean() {
        let github = fake("ghp_", "a", 36);
        let aws = fake("AKIA", "B", 16);
        let wrapped = format!("bundle={github}suffix;encoded=Z{aws}Q");
        assert!(
            kinds_in(wrapped).is_empty(),
            "embedded substrings are not standalone credentials"
        );

        let standalone = kinds_in(format!("bundle=\"{github}\"; aws: {aws}"));
        assert!(standalone.contains(&"GitHub personal access token"));
        assert!(standalone.contains(&"AWS access key id"));
    }

    #[test]
    fn redaction_only_blanks_boundary_valid_matches() {
        let token = fake("ghp_", "a", 36);
        let text = format!("x{token}y/{token}.md");
        assert_eq!(redact_path(&text), format!("x{token}y/\u{2026}.md"));
    }

    #[test]
    fn a_secret_in_a_file_name_is_flagged_and_redacted() {
        let token = fake("ghp_", "a", 36);
        let store = store_of(vec![(&format!("sources/{token}.md"), "clean".into())]);
        let hits = scan_store(&store);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].in_path);
        assert_eq!(hits[0].kind, "GitHub personal access token");
        assert!(
            !hits[0].path.contains(&token),
            "the shown path must not carry the token: {}",
            hits[0].path
        );
        assert!(hits[0].path.starts_with("sources/"));
        // The exact path rides on the non-printable field, for quarantine.
        assert_eq!(hits[0].store_path, format!("sources/{token}.md"));
    }

    #[test]
    fn redact_path_blanks_matches_and_passes_clean_text_through() {
        let token = fake("xoxb-", "9", 10);
        let redacted = redact_path(&format!("notes/{token}.md"));
        assert!(!redacted.contains(&token), "got: {redacted}");
        assert_eq!(redacted, "notes/\u{2026}.md");
        assert_eq!(redact_path("notes/plain.md"), "notes/plain.md");
    }

    #[test]
    fn assets_manifest_content_is_scanned() {
        let mut store = store_of(vec![("a.md", "clean".into())]);
        store.assets = Some(format!("{{\"note\":\"{}\"}}", fake("AKIA", "C", 16)));
        let hits = scan_store(&store);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "assets.jsonl");
        assert_eq!(hits[0].kind, "AWS access key id");
    }

    #[test]
    fn a_clean_store_has_no_hits() {
        let store = store_of(vec![(
            "notes/plan.md",
            "rotate keys quarterly; store them in the password manager".into(),
        )]);
        assert!(scan_store(&store).is_empty());
    }
}
