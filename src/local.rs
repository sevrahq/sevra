//! `.sevralocal` — the store's local scope: files that are part of the brain
//! but never part of the cargo. One store-relative POSIX path or glob per
//! line at the store root; `#`-prefixed lines and blank lines are skipped.
//! Matching is byte-wise and case-sensitive against the same store-relative
//! POSIX paths the push walk computes — no case folding, no normalization.
//! The list itself never rides a push: the walk's dot-skip already excludes
//! every dotfile (pinned by a store test).
//!
//! Two hub files must always ride and can never be kept home: `DB.md` (the
//! store config) and `assets.jsonl` (the asset manifest). The COMPILED entry
//! set is evaluated against those two literal names — which also catches
//! broad globs like `**` — and a set that covers either is refused at load,
//! so push, scan, and quarantine all fail the same way. A secret inside
//! those two files is an edit case the push scanner already flags.

use std::fs;
use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// The list's name at the store root.
pub const FILE_NAME: &str = ".sevralocal";

/// The two files that ride every push and can never be kept home.
pub const MUST_RIDE: [&str; 2] = ["DB.md", "assets.jsonl"];

#[derive(Debug)]
pub struct LocalScope {
    /// The compiled entry set.
    set: GlobSet,
    /// Effective (non-comment, non-blank) entry count.
    effective: usize,
    /// The file's verbatim text — `secrets quarantine` preserves it exactly
    /// and only appends.
    raw: String,
}

impl LocalScope {
    /// True when `rel` (a store-relative POSIX path) is kept home.
    pub fn keeps_home(&self, rel: &str) -> bool {
        self.set.is_match(rel)
    }

    /// True when the scope has at least one effective entry — the state that
    /// also keeps derived catalogs home.
    pub fn active(&self) -> bool {
        self.effective > 0
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

/// Load `<root>/.sevralocal`. `Ok(None)` when the file does not exist; `Err`
/// on an unreadable file, an entry that does not compile as a glob, or a set
/// that covers a must-ride hub file. Error text passes through the secret
/// redactor before it can carry any entry spelling — an entry is often an
/// exact path whose NAME is the very secret being kept home.
pub fn load(root: &Path) -> Result<Option<LocalScope>, String> {
    let raw = match fs::read_to_string(root.join(FILE_NAME)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not read {FILE_NAME}: {e}")),
    };
    let mut builder = GlobSetBuilder::new();
    let mut effective = 0usize;
    for (idx, line) in raw.lines().enumerate() {
        // A trailing CR is a line-ending artifact (a Windows-edited list),
        // never entry bytes. Everything else is matched verbatim.
        let entry = line.strip_suffix('\r').unwrap_or(line);
        if entry.trim().is_empty() || entry.starts_with('#') {
            continue;
        }
        // backslash_escape(true) on every platform: the list travels WITH
        // the store across machines, so its matching must not differ by OS
        // (globset's default flips on Windows).
        let glob = GlobBuilder::new(entry)
            .backslash_escape(true)
            .build()
            .map_err(|e| {
                format!(
                    "{FILE_NAME} line {}: not a valid path or glob ({})",
                    idx + 1,
                    crate::scan::redact_path(&e.kind().to_string())
                )
            })?;
        builder.add(glob);
        effective += 1;
    }
    let set = builder
        .build()
        .map_err(|e| format!("{FILE_NAME}: {}", crate::scan::redact_path(&e.to_string())))?;
    // The structural guard: config and the asset manifest must ride.
    let covered: Vec<&str> = MUST_RIDE
        .iter()
        .copied()
        .filter(|name| set.is_match(name))
        .collect();
    if !covered.is_empty() {
        return Err(format!(
            "refusing this {FILE_NAME}: it covers {} — the store config and the asset manifest ride every push; a secret inside them is an edit, and the push scanner already flags it",
            covered.join(" and ")
        ));
    }
    Ok(Some(LocalScope {
        set,
        effective,
        raw,
    }))
}

/// The list's text after appending `new_entries`: existing lines preserved
/// verbatim, new entries appended in the given order, single trailing
/// newline. Pure — `secrets quarantine` writes the result, and nothing else
/// in sevra ever edits a store file.
pub fn append_entries(raw: &str, new_entries: &[String]) -> String {
    let mut out = raw.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for entry in new_entries {
        out.push_str(entry);
        out.push('\n');
    }
    out
}

/// An exact path as a `.sevralocal` entry: verbatim when it carries no glob
/// metacharacter, else with each metacharacter wrapped in a one-character
/// class (`[*]`) so the entry matches the literal file instead of
/// misparsing — an unclosed `[` in a filename must never brick the list.
pub fn entry_for(path: &str) -> String {
    if !path.contains(['*', '?', '[', ']', '{', '}', '\\']) {
        return path.to_string();
    }
    let mut out = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        match c {
            '*' | '?' | '[' | ']' | '{' | '}' => {
                out.push('[');
                out.push(c);
                out.push(']');
            }
            // Inside a class `\` still escapes (backslash_escape is on) —
            // double it so the class holds a literal backslash.
            '\\' => out.push_str("[\\\\]"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_of(text: &str) -> LocalScope {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join(FILE_NAME), text).unwrap();
        load(t.path()).unwrap().expect("scope loads")
    }

    #[test]
    fn absent_file_is_none() {
        let t = tempfile::tempdir().unwrap();
        assert!(load(t.path()).unwrap().is_none());
    }

    #[test]
    fn comments_and_blanks_are_skipped_and_crlf_tolerated() {
        let s = scope_of("# keep these home\n\n  \nprivate/**\r\nnotes/one.md\n");
        assert!(s.active());
        assert!(s.keeps_home("private/deep/file.md"));
        assert!(s.keeps_home("notes/one.md"));
        assert!(!s.keeps_home("notes/two.md"));
        assert!(!s.keeps_home("# keep these home"));
    }

    #[test]
    fn comment_only_list_is_inactive() {
        let s = scope_of("# nothing effective here\n");
        assert!(!s.active());
        assert!(!s.keeps_home("anything.md"));
    }

    #[test]
    fn matching_is_byte_wise_case_sensitive() {
        let s = scope_of("Notes/Plan.md\n");
        assert!(s.keeps_home("Notes/Plan.md"));
        assert!(!s.keeps_home("notes/plan.md"), "no case folding, ever");
    }

    #[test]
    fn must_ride_files_are_refused_literal_and_via_broad_globs() {
        for text in ["DB.md\n", "assets.jsonl\n", "**\n"] {
            let t = tempfile::tempdir().unwrap();
            fs::write(t.path().join(FILE_NAME), text).unwrap();
            let err = load(t.path()).unwrap_err();
            assert!(
                err.contains("ride every push"),
                "{text:?} must refuse: {err}"
            );
        }
    }

    #[test]
    fn invalid_glob_names_the_line_without_echoing_the_entry() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join(FILE_NAME), "# ok\nsome-entry-xyz[\n").unwrap();
        let err = load(t.path()).unwrap_err();
        assert!(err.contains("line 2"), "names the line: {err}");
        assert!(
            !err.contains("some-entry-xyz"),
            "never echoes the entry: {err}"
        );
    }

    #[test]
    fn append_preserves_verbatim_and_ends_with_one_newline() {
        // Create-from-absent.
        assert_eq!(append_entries("", &["a.md".into()]), "a.md\n");
        // Existing lines (comments included) stay byte-identical; a missing
        // final newline is repaired before the first append.
        let raw = "# mine\nz.md";
        assert_eq!(
            append_entries(raw, &["a.md".into(), "b.md".into()]),
            "# mine\nz.md\na.md\nb.md\n"
        );
        // Appending nothing changes nothing that already ends in a newline.
        assert_eq!(append_entries("x.md\n", &[]), "x.md\n");
    }

    #[test]
    fn entry_for_escapes_metacharacters_into_literal_matches() {
        assert_eq!(entry_for("plain/path.md"), "plain/path.md");
        let weird = "notes/[draft] a*b?.md";
        let entry = entry_for(weird);
        let glob = GlobBuilder::new(&entry)
            .backslash_escape(true)
            .build()
            .expect("escaped entry compiles");
        let m = glob.compile_matcher();
        assert!(m.is_match(weird), "matches the literal file: {entry}");
        assert!(!m.is_match("notes/d axb.md"), "no wildcard semantics leak");
        // And the escaped entry round-trips through a whole scope.
        let s = scope_of(&format!("{entry}\n"));
        assert!(s.keeps_home(weird));
    }
}
