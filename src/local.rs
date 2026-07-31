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
use std::io::Read;
use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// The list's name at the store root.
pub const FILE_NAME: &str = ".sevralocal";

/// The two files that ride every push and can never be kept home.
pub const MUST_RIDE: [&str; 2] = ["DB.md", "assets.jsonl"];

/// A local-scope list is configuration, not bulk data. Bound every dimension
/// before glob compilation so a hostile or concurrently-growing file cannot
/// turn any store operation into an unbounded allocation or CPU task.
pub(crate) const MAX_SCOPE_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_SCOPE_LINE_BYTES: usize = 4096;
pub(crate) const MAX_SCOPE_ENTRIES: usize = 10_000;

fn read_scope_bounded<R: Read>(reader: R, advertised_len: u64) -> Result<Vec<u8>, String> {
    if advertised_len > MAX_SCOPE_BYTES {
        return Err(format!(
            "refusing {FILE_NAME}: the local-scope file exceeds {MAX_SCOPE_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::with_capacity(advertised_len as usize);
    reader
        .take(MAX_SCOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {FILE_NAME}: {e}"))?;
    if bytes.len() as u64 > MAX_SCOPE_BYTES {
        return Err(format!(
            "refusing {FILE_NAME}: the local-scope file grew beyond {MAX_SCOPE_BYTES} bytes while reading"
        ));
    }
    Ok(bytes)
}

fn validate_scope_shape(raw: &str) -> Result<usize, String> {
    if raw.len() as u64 > MAX_SCOPE_BYTES {
        return Err(format!(
            "refusing {FILE_NAME}: the local-scope file exceeds {MAX_SCOPE_BYTES} bytes"
        ));
    }
    let mut effective = 0usize;
    for (idx, line) in raw.lines().enumerate() {
        if line.len() > MAX_SCOPE_LINE_BYTES {
            return Err(format!(
                "refusing {FILE_NAME}: line {} exceeds {MAX_SCOPE_LINE_BYTES} bytes",
                idx + 1
            ));
        }
        let entry = line.strip_suffix('\r').unwrap_or(line);
        if entry.trim().is_empty() || entry.starts_with('#') {
            continue;
        }
        effective += 1;
        if effective > MAX_SCOPE_ENTRIES {
            return Err(format!(
                "refusing {FILE_NAME}: it has more than {MAX_SCOPE_ENTRIES} effective entries"
            ));
        }
    }
    Ok(effective)
}

fn read_scope_file(root: &Path) -> Result<Option<String>, String> {
    let path = root.join(FILE_NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not inspect {FILE_NAME}: {e}")),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing {FILE_NAME}: the local-scope file must not be a symlink"
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "refusing {FILE_NAME}: the local-scope path is not a regular file"
        ));
    }

    let secure_root =
        fs::canonicalize(root).map_err(|e| format!("could not resolve store directory: {e}"))?;
    let file = crate::safe_path::open_regular(&secure_root, FILE_NAME)
        .map_err(|e| format!("could not open {FILE_NAME} without following links: {e}"))?
        .ok_or_else(|| format!("{FILE_NAME} disappeared while opening it"))?;
    let held_len = file
        .metadata()
        .map_err(|e| format!("could not inspect the opened {FILE_NAME}: {e}"))?
        .len();
    let bytes = read_scope_bounded(file, held_len)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| format!("could not read {FILE_NAME} as UTF-8: {e}"))
}

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
    let raw = match read_scope_file(root)? {
        Some(raw) => raw,
        None => return Ok(None),
    };
    let expected_effective = validate_scope_shape(&raw)?;
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
    debug_assert_eq!(effective, expected_effective);
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
pub fn entry_for(path: &str) -> Result<String, String> {
    if path.chars().any(char::is_control) {
        return Err(format!(
            "refusing to write {FILE_NAME}: a matched file path contains control characters"
        ));
    }
    if !path.starts_with('#') && !path.contains(['*', '?', '[', ']', '{', '}', '\\']) {
        return Ok(path.to_string());
    }
    let mut out = String::with_capacity(path.len() + 8);
    for (index, c) in path.chars().enumerate() {
        match c {
            // A raw leading `#` is the line format's comment marker. Express
            // it as a one-character class so quarantine really keeps a
            // `#secret.md` file home instead of silently writing a comment.
            '#' if index == 0 => out.push_str("[#]"),
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
    Ok(out)
}

/// Atomically replace `<root>/.sevralocal` without ever opening the
/// destination for writing. A symlink present at inspection is refused for a
/// clear operator signal; one planted after inspection is atomically replaced
/// through a held parent directory handle, never followed. The temporary file
/// is created 0600 in the same directory and synced before the rename.
pub fn write(root: &Path, body: &str) -> Result<(), String> {
    validate_scope_shape(body)?;
    let path = root.join(FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "refusing to write {FILE_NAME}: the local-scope file is a symlink"
            ));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(format!(
                "refusing to write {FILE_NAME}: the local-scope path is not a regular file"
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("could not inspect {FILE_NAME}: {e}")),
    }

    let secure_root =
        fs::canonicalize(root).map_err(|e| format!("could not resolve store directory: {e}"))?;
    crate::safe_path::atomic_write(&secure_root, FILE_NAME, body.as_bytes(), false, 0o600)
        .map_err(|e| format!("could not atomically replace {FILE_NAME}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
    fn exact_byte_limit_is_accepted() {
        let t = tempfile::tempdir().unwrap();
        let body = "#\n".repeat((MAX_SCOPE_BYTES / 2) as usize);
        assert_eq!(body.len() as u64, MAX_SCOPE_BYTES);
        fs::write(t.path().join(FILE_NAME), body).unwrap();
        assert!(!load(t.path()).unwrap().unwrap().active());
    }

    #[test]
    fn oversized_sparse_file_is_rejected_before_reading() {
        let t = tempfile::tempdir().unwrap();
        let file = fs::File::create(t.path().join(FILE_NAME)).unwrap();
        file.set_len(MAX_SCOPE_BYTES + 1).unwrap();
        let err = load(t.path()).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn concurrent_growth_past_limit_is_rejected() {
        let bytes = vec![b'#'; (MAX_SCOPE_BYTES + 1) as usize];
        let err = read_scope_bounded(Cursor::new(bytes), MAX_SCOPE_BYTES).unwrap_err();
        assert!(err.contains("grew beyond"), "{err}");
    }

    #[test]
    fn line_and_effective_entry_limits_are_exact() {
        let t = tempfile::tempdir().unwrap();
        let exact_line = format!("#{}\n", "a".repeat(MAX_SCOPE_LINE_BYTES - 1));
        fs::write(t.path().join(FILE_NAME), exact_line).unwrap();
        assert!(load(t.path()).unwrap().is_some());

        let oversized_line = format!("#{}\n", "a".repeat(MAX_SCOPE_LINE_BYTES));
        fs::write(t.path().join(FILE_NAME), oversized_line).unwrap();
        assert!(load(t.path()).unwrap_err().contains("line 1 exceeds"));

        let exact_entries = (0..MAX_SCOPE_ENTRIES)
            .map(|idx| format!("private/{idx}\n"))
            .collect::<String>();
        fs::write(t.path().join(FILE_NAME), exact_entries).unwrap();
        assert_eq!(
            load(t.path()).unwrap().unwrap().effective,
            MAX_SCOPE_ENTRIES
        );

        let too_many_entries = (0..=MAX_SCOPE_ENTRIES)
            .map(|idx| format!("private/{idx}\n"))
            .collect::<String>();
        fs::write(t.path().join(FILE_NAME), too_many_entries).unwrap();
        assert!(load(t.path())
            .unwrap_err()
            .contains("more than 10000 effective entries"));
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
        assert_eq!(entry_for("plain/path.md").unwrap(), "plain/path.md");
        let weird = "notes/[draft] a*b?.md";
        let entry = entry_for(weird).unwrap();
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
        let comment_shaped = entry_for("#credential.md").unwrap();
        assert_eq!(comment_shaped, "[#]credential.md");
        let s = scope_of(&format!("{comment_shaped}\n"));
        assert!(s.keeps_home("#credential.md"));
    }

    #[test]
    fn entry_for_refuses_controls_that_would_create_new_scope_lines() {
        for path in [
            "notes/a\ncommand.md",
            "notes/a\rb.md",
            "notes/a\u{1b}[31m.md",
        ] {
            assert!(entry_for(path).unwrap_err().contains("control characters"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_and_write_never_follow_a_scope_symlink() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("outside");
        let store = t.path().join("store");
        fs::create_dir(&store).unwrap();
        std::os::unix::fs::symlink(&target, store.join(FILE_NAME)).unwrap();

        assert!(load(&store).unwrap_err().contains("must not be a symlink"));
        assert!(write(&store, "notes/a.md\n")
            .unwrap_err()
            .contains("is a symlink"));
        assert!(!target.exists(), "the dangling target was never created");
    }

    #[test]
    fn write_atomically_replaces_a_regular_scope_file() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join(FILE_NAME), "old.md\n").unwrap();
        write(t.path(), "new.md\n").unwrap();
        assert_eq!(
            fs::read_to_string(t.path().join(FILE_NAME)).unwrap(),
            "new.md\n"
        );
        assert!(load(t.path()).unwrap().unwrap().keeps_home("new.md"));
    }

    #[test]
    fn rejected_write_does_not_mutate_scope_file() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join(FILE_NAME);
        fs::write(&path, "old.md\n").unwrap();
        let oversized = "x".repeat(MAX_SCOPE_BYTES as usize + 1);
        assert!(write(t.path(), &oversized).unwrap_err().contains("exceeds"));
        assert_eq!(fs::read_to_string(path).unwrap(), "old.md\n");
    }
}
