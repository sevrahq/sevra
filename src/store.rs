//! Local db.md store read for `push`: walk a directory, collect `.md` files
//! (relative POSIX paths) + an optional `assets.jsonl`, following symlinks with
//! cycle protection (Obsidian-style vaults symlink shared folders), skipping
//! dotfiles. Mirrors the TS CLI's readStoreFiles.

use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use serde::Serialize;

#[derive(Serialize)]
pub struct StoreFile {
    pub path: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct Store {
    pub files: Vec<StoreFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assets: Option<String>,
}

/// Build the immutable whole-store ZIP used by the hub's large-brain path.
/// Entries are path-sorted with fixed metadata so retrying an unchanged store
/// produces the same bytes and therefore the same content address.
pub fn build_pack(store: &Store) -> std::io::Result<Vec<u8>> {
    let mut entries: Vec<(&str, &[u8])> = store
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_bytes()))
        .collect();
    if let Some(assets) = store.assets.as_deref() {
        entries.push(("assets.jsonl", assets.as_bytes()));
    }
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o600);
    for (path, bytes) in entries {
        writer
            .start_file(path, options)
            .map_err(std::io::Error::other)?;
        writer.write_all(bytes)?;
    }
    writer
        .finish()
        .map(Cursor::into_inner)
        .map_err(std::io::Error::other)
}

/// How many of the largest files the walk keeps for limit-refusal reporting.
const LARGEST_TRACKED: usize = 10;

/// What the walk saw: every file that counts toward the hub's snapshot
/// limits, whether or not its content was read. O(1) memory over any store
/// size — a cap refusal can name honest totals and the biggest offenders
/// without holding the whole tree.
#[derive(Debug)]
pub struct WalkStats {
    pub files: usize,
    pub bytes: u64,
    /// The largest counted files (path, bytes), descending, at most
    /// `LARGEST_TRACKED`.
    pub largest: Vec<(String, u64)>,
}

#[derive(Debug)]
pub enum StoreError {
    /// The store's counted files exceed the byte cap. The walk finished
    /// metadata-only past the cap, so the stats are the real totals.
    OverCap(WalkStats),
    Io(std::io::Error),
}

/// Keep `largest` the descending top-`LARGEST_TRACKED` list.
pub(crate) fn note_largest(largest: &mut Vec<(String, u64)>, rel: &str, len: u64) {
    let pos = largest.partition_point(|(_, l)| *l >= len);
    if pos < LARGEST_TRACKED {
        largest.insert(pos, (rel.to_string(), len));
        largest.truncate(LARGEST_TRACKED);
    }
}

fn rel_posix(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Read a file, naming it in the error — "stream did not contain valid UTF-8"
/// with no path is undebuggable in a 10k-file vault.
fn read_named(full: &Path, rel: &str) -> std::io::Result<String> {
    fs::read_to_string(full).map_err(|e| std::io::Error::other(format!("{rel}: {e}")))
}

struct WalkState {
    store: Store,
    stats: WalkStats,
    /// Remaining read budget (max + 1). 0 = over the cap: stop reading
    /// content, keep walking so the stats stay honest.
    budget: u64,
}

fn walk(
    root: &Path,
    dir: &Path,
    visited: &mut HashSet<std::path::PathBuf>,
    st: &mut WalkState,
) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let full = entry.path();
        // Resolve type via metadata (follows symlinks); a dangling link is skipped.
        let meta = match fs::metadata(&full) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            // Cycle guard on the real path.
            let real = fs::canonicalize(&full).unwrap_or(full.clone());
            if !visited.insert(real) {
                continue;
            }
            walk(root, &full, visited, st)?;
        } else if meta.is_file() {
            let rel = rel_posix(root, &full);
            let counts = rel == "assets.jsonl" || rel.to_lowercase().ends_with(".md");
            if !counts {
                continue;
            }
            st.stats.files += 1;
            st.stats.bytes = st.stats.bytes.saturating_add(meta.len());
            note_largest(&mut st.stats.largest, &rel, meta.len());
            // Size-gate BEFORE reading: past the budget, stop touching file
            // contents — the rest of the walk only counts and sizes, so the
            // refusal can report what was actually found.
            st.budget = st.budget.saturating_sub(meta.len());
            if st.budget == 0 {
                continue;
            }
            if rel == "assets.jsonl" {
                st.store.assets = Some(read_named(&full, &rel)?);
            } else {
                let content = read_named(&full, &rel)?;
                st.store.files.push(StoreFile { path: rel, content });
            }
        }
    }
    Ok(())
}

/// Read the store, refusing once raw bytes exceed `max_bytes` — a store whose
/// raw file bytes exceed the cap cannot fit under it as JSON either (escaping
/// only grows), so a symlinked multi-GB vault is never read into memory
/// before a post-hoc check. On the cap refusal the walk continues without
/// reading, so `StoreError::OverCap` carries the store's true totals and its
/// largest files.
pub fn read_store(dir: &str, max_bytes: u64) -> Result<(Store, WalkStats), StoreError> {
    let root = Path::new(dir);
    let mut st = WalkState {
        store: Store {
            files: Vec::new(),
            assets: None,
        },
        stats: WalkStats {
            files: 0,
            bytes: 0,
            largest: Vec::new(),
        },
        // budget hits zero exactly when the running total EXCEEDS max_bytes —
        // a store of exactly max_bytes raw bytes is still allowed through to
        // the exact JSON-size check in `push`.
        budget: max_bytes.saturating_add(1),
    };
    let mut visited = HashSet::new();
    visited.insert(fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()));
    match walk(root, root, &mut visited, &mut st) {
        Ok(()) if st.budget == 0 => Err(StoreError::OverCap(st.stats)),
        Ok(()) => Ok((st.store, st.stats)),
        Err(e) => Err(StoreError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &std::path::Path, rel: &str, content: &[u8]) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    #[test]
    fn collects_md_and_assets_skips_dotfiles_and_others() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"alpha");
        write(t.path(), "sub/b.MD", b"beta"); // case-insensitive .md
        write(t.path(), "assets.jsonl", b"{}");
        write(t.path(), ".hidden.md", b"nope");
        write(t.path(), ".obsidian/cfg.md", b"nope");
        write(t.path(), "notes.txt", b"nope");
        write(t.path(), "sub/assets.jsonl", b"nope"); // only ROOT assets.jsonl counts
        let (s, stats) = read_store(t.path().to_str().unwrap(), 1024).unwrap();
        let mut paths: Vec<_> = s.files.iter().map(|f| f.path.clone()).collect();
        paths.sort();
        assert_eq!(paths, ["a.md", "sub/b.MD"]);
        assert_eq!(s.assets.as_deref(), Some("{}"));
        assert_eq!(stats.files, 3, "md files + the root assets.jsonl");
        assert_eq!(stats.bytes, 11);
    }

    #[test]
    fn cap_allows_exactly_max_refuses_one_more() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", &[b'x'; 100]);
        assert!(read_store(t.path().to_str().unwrap(), 100).is_ok());
        write(t.path(), "b.md", b"y");
        match read_store(t.path().to_str().unwrap(), 100) {
            Err(StoreError::OverCap(_)) => {} // cap refusal, before reading past it
            other => panic!("expected cap refusal, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn over_cap_stats_report_true_totals_and_largest() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "big.md", &[b'x'; 60]);
        write(t.path(), "mid.md", &[b'x'; 50]);
        write(t.path(), "small.md", &[b'x'; 10]);
        match read_store(t.path().to_str().unwrap(), 100) {
            Err(StoreError::OverCap(stats)) => {
                assert_eq!(stats.files, 3, "the walk keeps counting past the cap");
                assert_eq!(stats.bytes, 120, "totals cover the whole store");
                let paths: Vec<&str> = stats.largest.iter().map(|(p, _)| p.as_str()).collect();
                assert_eq!(
                    paths,
                    ["big.md", "mid.md", "small.md"],
                    "descending by size"
                );
            }
            other => panic!("expected cap refusal, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn note_largest_keeps_the_descending_top_ten() {
        let mut largest = Vec::new();
        for n in 0..25u64 {
            note_largest(&mut largest, &format!("f{n}.md"), n);
        }
        assert_eq!(largest.len(), LARGEST_TRACKED);
        let sizes: Vec<u64> = largest.iter().map(|(_, l)| *l).collect();
        assert_eq!(sizes, [24, 23, 22, 21, 20, 19, 18, 17, 16, 15]);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cycle_terminates_and_dedupes() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a/note.md", b"hi");
        std::os::unix::fs::symlink(t.path(), t.path().join("a/loop")).unwrap();
        let (s, _) = read_store(t.path().to_str().unwrap(), 4096).unwrap();
        assert_eq!(s.files.len(), 1, "the cycled file must be collected once");
    }

    #[test]
    fn non_utf8_read_error_names_the_file() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "bad.md", &[0xff, 0xfe, b'x']);
        match read_store(t.path().to_str().unwrap(), 4096) {
            Err(StoreError::Io(e)) => assert!(e.to_string().contains("bad.md"), "got: {e}"),
            other => panic!("expected named read error, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn pack_is_deterministic_and_contains_the_complete_store() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "z.md", b"last");
        write(t.path(), "a.md", b"first");
        write(t.path(), "assets.jsonl", b"{}\n");
        let (store, _) = read_store(t.path().to_str().unwrap(), 4096).unwrap();
        let one = build_pack(&store).unwrap();
        let two = build_pack(&store).unwrap();
        assert_eq!(one, two);
        let mut archive = zip::ZipArchive::new(Cursor::new(one)).unwrap();
        assert_eq!(archive.len(), 3);
        assert_eq!(archive.by_index(0).unwrap().name(), "a.md");
        assert_eq!(archive.by_index(1).unwrap().name(), "assets.jsonl");
        assert_eq!(archive.by_index(2).unwrap().name(), "z.md");
    }
}
