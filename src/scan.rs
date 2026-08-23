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

pub(crate) const PATH_HEURISTIC_KIND: &str = "credential-related filename";
const PATH_SINGLE_TOKENS: &[&str] = &[
    "password",
    "passwords",
    "passwd",
    "passwds",
    "credential",
    "credentials",
    "secret",
    "secrets",
];
const PATH_TOKEN_PAIRS: &[(&str, &str)] = &[
    ("api", "key"),
    ("api", "keys"),
    ("access", "key"),
    ("access", "keys"),
    ("private", "key"),
    ("private", "keys"),
    ("app", "password"),
    ("app", "passwords"),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SecretSpan {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
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

fn suspicious_path_segment(segment: &str) -> bool {
    let stem = segment
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(segment);
    let tokens: Vec<String> = stem
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect();
    tokens
        .iter()
        .any(|token| PATH_SINGLE_TOKENS.contains(&token.as_str()))
        || tokens
            .windows(2)
            .any(|pair| PATH_TOKEN_PAIRS.contains(&(pair[0].as_str(), pair[1].as_str())))
}

fn redact_suspicious_path_segments(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if suspicious_path_segment(segment) {
                "\u{2026}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Exact value spans for `secrets adopt`. Unlike the refusal scanner's
/// kind-only result, this enumerates every occurrence and expands the two
/// prefix patterns to the complete credential: the full 1Password share URL
/// token and the complete PEM private-key block. An incomplete PEM block is a
/// refusal, never a partial redaction that leaves key material behind.
pub(crate) fn content_secret_spans(text: &str) -> Result<Vec<SecretSpan>, String> {
    let sc = scanner();
    let mut spans = Vec::new();
    for index in sc.set.matches(text) {
        for (matched_start, matched_end) in
            bounded_spans(&sc.each[index], text, right_boundary(index))
        {
            let kind = PATTERNS[index].0;
            let start =
                if kind == "1Password share link" && text[..matched_start].ends_with("https://") {
                    matched_start - "https://".len()
                } else {
                    matched_start
                };
            let end = match kind {
                "1Password share link" => {
                    let bytes = text.as_bytes();
                    let mut end = matched_end;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'-' | b'_'))
                    {
                        end += 1;
                    }
                    if end == matched_end {
                        return Err("an incomplete 1Password share link cannot be adopted".into());
                    }
                    end
                }
                "private key (PEM block)" => {
                    let begin = &text[start..matched_end];
                    let end_marker = begin.replacen("BEGIN", "END", 1);
                    let Some(relative_end) = text[matched_end..].find(&end_marker) else {
                        return Err(
                            "an unterminated PEM private-key block cannot be adopted".into()
                        );
                    };
                    matched_end + relative_end + end_marker.len()
                }
                _ => matched_end,
            };
            spans.push(SecretSpan { start, end, kind });
        }
    }
    spans.sort_by_key(|span| (span.start, span.end));
    spans.dedup_by_key(|span| (span.start, span.end));
    for pair in spans.windows(2) {
        if pair[0].end > pair[1].start {
            return Err("overlapping secret formats cannot be adopted safely".into());
        }
    }
    Ok(spans)
}

/// Scan a store-relative path. Asset transport uses this independently of
/// content inspection so a binary or oversized asset can still be refused
/// when its filename itself carries a credential.
pub(crate) fn scan_path(path: &str) -> Vec<SecretHit> {
    let matches = matching_patterns(path);
    let heuristic = path.split('/').any(suspicious_path_segment);
    if matches.is_empty() && !heuristic {
        return Vec::new();
    }
    let shown = redact_suspicious_path_segments(&redact_path(path));
    let mut hits: Vec<SecretHit> = matches
        .into_iter()
        .map(|index| SecretHit {
            path: shown.clone(),
            store_path: path.to_string(),
            kind: PATTERNS[index].0,
            in_path: true,
        })
        .collect();
    if heuristic {
        hits.push(SecretHit {
            path: shown,
            store_path: path.to_string(),
            kind: PATH_HEURISTIC_KIND,
            in_path: true,
        });
    }
    hits
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
    fn public_pattern_spec_is_the_executable_scanner_contract() {
        let spec: serde_json::Value =
            serde_json::from_str(include_str!("../spec/secret-patterns-v1.json")).unwrap();
        assert_eq!(spec["version"], 1);
        let patterns = spec["contentPatterns"].as_array().unwrap();
        assert_eq!(patterns.len(), PATTERNS.len());
        for (index, (kind, regex)) in PATTERNS.iter().enumerate() {
            assert_eq!(patterns[index]["kind"], *kind);
            assert_eq!(patterns[index]["regex"], *regex);
            assert_eq!(patterns[index]["rightBoundary"], right_boundary(index));
        }
        let heuristic = &spec["pathHeuristic"];
        assert_eq!(heuristic["kind"], PATH_HEURISTIC_KIND);
        let singles: Vec<&str> = heuristic["singleTokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(singles, PATH_SINGLE_TOKENS);
        let pairs: Vec<(&str, &str)> = heuristic["tokenPairs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                let pair = pair.as_array().unwrap();
                (pair[0].as_str().unwrap(), pair[1].as_str().unwrap())
            })
            .collect();
        assert_eq!(pairs, PATH_TOKEN_PAIRS);
    }

    #[test]
    fn credential_related_filenames_are_suspect_without_exposing_the_segment() {
        for path in [
            "records/password-hunter.md",
            "sources/config-secrets-example-json.md",
            "assets/private_key.txt",
            "records/app-password.md",
        ] {
            let hits = scan_path(path);
            assert!(
                hits.iter().any(|hit| hit.kind == PATH_HEURISTIC_KIND),
                "heuristic missed {path}"
            );
            assert_eq!(hits[0].store_path, path);
            assert!(hits[0].path.contains('\u{2026}'));
            assert!(!hits[0].path.contains(path.rsplit('/').next().unwrap()));
        }
    }

    #[test]
    fn credential_filename_heuristic_avoids_adjacent_concepts() {
        for path in [
            "records/passwordless-auth.md",
            "records/secretariat.md",
            "sources/tokenization.md",
            "records/api-client.md",
            "records/key-design.md",
        ] {
            assert!(scan_path(path).is_empty(), "false positive on {path}");
        }
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

    #[test]
    fn adopt_spans_enumerate_duplicates_and_cover_complete_compound_values() {
        let github = fake("ghp_", "a", 36);
        let share = "https://share.1password.com/s#abc_DEF-123";
        // Assemble hostile fixture markers at runtime so source scanning stays
        // independent from the product scanner this test is exercising.
        let pem = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "YWJj",
            "-----END RSA PRIVATE KEY-----",
        ]
        .join("\n");
        let text = format!("one={github}\ntwo={github}\nshare={share}\nkey={pem}\n");
        let spans = content_secret_spans(&text).unwrap();
        let values: Vec<&str> = spans
            .iter()
            .map(|span| &text[span.start..span.end])
            .collect();
        assert_eq!(
            values,
            vec![github.as_str(), github.as_str(), share, pem.as_str()]
        );
    }

    #[test]
    fn adopt_refuses_an_unterminated_pem_instead_of_redacting_only_the_header() {
        let incomplete = ["-----BEGIN PRIVATE", " KEY-----\nYWJj"].concat();
        let error = content_secret_spans(&incomplete).unwrap_err();
        assert!(error.contains("unterminated PEM"), "{error}");
    }
}
