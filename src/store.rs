//! Local db.md store read for `push`: walk a directory, collect `.md` files
//! (relative POSIX paths) + an optional `assets.jsonl`. Symlinks may point
//! elsewhere inside the store, but any link that resolves outside is refused:
//! a cloned brain must never smuggle ~/.ssh or another sibling tree into a
//! push. Cycles are deduplicated and dotfiles are skipped. A `.sevralocal` at the
//! store root (see `crate::local`) keeps matching files home: excluded from
//! the collected store, counted separately in the stats.

use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use serde::Serialize;

use crate::local::LocalScope;

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
    /// Files `.sevralocal` kept home: excluded from the collected store AND
    /// from every limit total above — a kept-home file never rides, so it
    /// never counts toward the hub's snapshot caps.
    pub kept_home: usize,
    /// Derived `index.md` catalogs excluded because the local scope is
    /// active — catalogs carry every file's name/title/summary, kept-home
    /// files included, and the hub rebuilds its own from what rides.
    pub catalogs_kept: usize,
}

#[derive(Debug)]
pub enum StoreError {
    /// The store's counted files exceed the byte cap. The walk finished
    /// metadata-only past the cap, so the stats are the real totals.
    OverCap(WalkStats),
    /// The store's `.sevralocal` is unreadable, uncompilable, or covers a
    /// must-ride hub file. The message is complete and never echoes entry
    /// bytes that could themselves be a secret.
    Scope(String),
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
    root_real: &Path,
    dir: &Path,
    visited: &mut HashSet<std::path::PathBuf>,
    st: &mut WalkState,
    scope: Option<&LocalScope>,
) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let entry_name = entry.file_name();
        let name = entry_name.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "refusing a store entry whose name is not valid UTF-8",
            )
        })?;
        if name.starts_with('.') {
            continue;
        }
        let full = entry.path();
        // Resolve once and enforce the real-path boundary before metadata,
        // sizing, or content reads. Reading the canonical file also avoids a
        // leaf symlink swap between the containment check and fs::read.
        let real = match fs::canonicalize(&full) {
            Ok(path) => path,
            Err(_) => continue, // dangling or unreadable links do not ride
        };
        if !real.starts_with(root_real) {
            let rel = rel_posix(root, &full);
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{rel}: refusing a symlink that resolves outside the store"),
            ));
        }
        let meta = match fs::metadata(&real) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            // Cycle guard on the real path.
            if !visited.insert(real) {
                continue;
            }
            walk(root, root_real, &full, visited, st, scope)?;
        } else if meta.is_file() {
            if !visited.insert(real.clone()) {
                continue;
            }
            let rel = rel_posix(root, &full);
            let counts = rel == "assets.jsonl" || rel.to_lowercase().ends_with(".md");
            if !counts {
                // (`index.jsonl` never reaches the collected store on any
                // path: it is not `.md` and only the ROOT `assets.jsonl`
                // counts, so it needs no kept-home handling below.)
                continue;
            }
            if let Some(scope) = scope {
                // Kept-home exclusions happen BEFORE any counting: a file
                // that never rides must not count toward the hub's snapshot
                // limits either. (`DB.md` and `assets.jsonl` can never land
                // here — a scope covering them is refused at load.)
                if scope.keeps_home(&rel) {
                    st.stats.kept_home += 1;
                    continue;
                }
                // An ACTIVE local scope also keeps every derived catalog
                // home: catalogs list every file's name/title/summary —
                // kept-home files included — and the hub rebuilds its own
                // from what actually rides.
                if scope.active() && rel.rsplit('/').next() == Some("index.md") {
                    st.stats.catalogs_kept += 1;
                    continue;
                }
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
                st.store.assets = Some(read_named(&real, &rel)?);
            } else {
                let content = read_named(&real, &rel)?;
                st.store.files.push(StoreFile { path: rel, content });
            }
        }
    }
    Ok(())
}

/// Read the store as a push would carry it: the walk honors `.sevralocal`
/// (kept-home files and, when the scope is active, derived catalogs are
/// excluded and counted in the stats), refusing once raw riding bytes exceed
/// `max_bytes` — a store whose raw file bytes exceed the cap cannot fit
/// under it as JSON either (escaping only grows), so a symlinked multi-GB
/// vault is never read into memory before a post-hoc check. On the cap
/// refusal the walk continues without reading, so `StoreError::OverCap`
/// carries the store's true totals and its largest files.
pub fn read_store(dir: &str, max_bytes: u64) -> Result<(Store, WalkStats), StoreError> {
    let scope = crate::local::load(Path::new(dir)).map_err(StoreError::Scope)?;
    read_store_impl(dir, max_bytes, scope.as_ref())
}

/// The FULL store, `.sevralocal` ignored — `secrets quarantine` reads this:
/// its whole job is seeing hits inside kept-home files.
pub fn read_store_unscoped(dir: &str, max_bytes: u64) -> Result<(Store, WalkStats), StoreError> {
    read_store_impl(dir, max_bytes, None)
}

fn read_store_impl(
    dir: &str,
    max_bytes: u64,
    scope: Option<&LocalScope>,
) -> Result<(Store, WalkStats), StoreError> {
    let root = Path::new(dir);
    let root_real = fs::canonicalize(root).map_err(StoreError::Io)?;
    let mut st = WalkState {
        store: Store {
            files: Vec::new(),
            assets: None,
        },
        stats: WalkStats {
            files: 0,
            bytes: 0,
            largest: Vec::new(),
            kept_home: 0,
            catalogs_kept: 0,
        },
        // budget hits zero exactly when the running total EXCEEDS max_bytes —
        // a store of exactly max_bytes raw bytes is still allowed through to
        // the exact JSON-size check in `push`.
        budget: max_bytes.saturating_add(1),
    };
    let mut visited = HashSet::new();
    visited.insert(root_real.clone());
    match walk(root, &root_real, root, &mut visited, &mut st, scope) {
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

    #[test]
    fn sevralocal_keeps_files_home_and_out_of_every_total() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"ride");
        write(t.path(), "notes/b.md", b"ride2");
        write(t.path(), "private/keys.md", b"stay-home");
        write(t.path(), ".sevralocal", b"# mine\n\nprivate/**\r\n");
        let (s, stats) = read_store(t.path().to_str().unwrap(), 1024).unwrap();
        let mut paths: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, ["a.md", "notes/b.md"]);
        assert_eq!(stats.kept_home, 1);
        assert_eq!(stats.files, 2, "kept-home files never count toward limits");
        assert_eq!(stats.bytes, 9, "kept-home bytes never count either");
        assert!(stats
            .largest
            .iter()
            .all(|(p, _)| !p.starts_with("private/")));
    }

    #[test]
    fn the_sevralocal_file_itself_never_rides_on_any_walk() {
        // The dot-skip invariant, pinned: the list is a dotfile, so BOTH the
        // scoped walk and quarantine's unscoped walk exclude and never count
        // it — the list of what stays home stays home too.
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"ride");
        write(t.path(), ".sevralocal", b"ghost.md\n");
        for (store, stats) in [
            read_store(t.path().to_str().unwrap(), 1024).unwrap(),
            read_store_unscoped(t.path().to_str().unwrap(), 1024).unwrap(),
        ] {
            assert_eq!(store.files.len(), 1);
            assert_eq!(store.files[0].path, "a.md");
            assert_eq!(stats.files, 1);
        }
    }

    #[test]
    fn active_sevralocal_keeps_derived_catalogs_home() {
        // Active by ENTRY, not by match: one effective entry (even one that
        // matches nothing) is enough to keep every `index.md` catalog home.
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"ride");
        write(t.path(), "index.md", b"catalog");
        write(t.path(), "sub/index.md", b"catalog2");
        write(t.path(), ".sevralocal", b"ghost.md\n");
        let (s, stats) = read_store(t.path().to_str().unwrap(), 1024).unwrap();
        let paths: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["a.md"]);
        assert_eq!(stats.kept_home, 0, "ghost.md matched nothing");
        assert_eq!(stats.catalogs_kept, 2);
    }

    #[test]
    fn without_sevralocal_or_with_an_inactive_one_catalogs_ride() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"ride");
        write(t.path(), "index.md", b"catalog");
        let read = |dir: &std::path::Path| {
            let (s, stats) = read_store(dir.to_str().unwrap(), 1024).unwrap();
            let mut paths: Vec<String> = s.files.iter().map(|f| f.path.clone()).collect();
            paths.sort();
            (paths, stats)
        };
        let (paths, stats) = read(t.path());
        assert_eq!(paths, ["a.md", "index.md"], "no list — catalogs ride");
        assert_eq!(stats.catalogs_kept, 0);
        // A comment-only list is inactive: still no catalog exclusion.
        write(t.path(), ".sevralocal", b"# nothing effective\n");
        let (paths, stats) = read(t.path());
        assert_eq!(paths, ["a.md", "index.md"]);
        assert_eq!(stats.catalogs_kept, 0);
    }

    #[test]
    fn sevralocal_matching_is_case_sensitive() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "notes.md", b"ride");
        write(t.path(), ".sevralocal", b"NOTES.md\n");
        let (s, stats) = read_store(t.path().to_str().unwrap(), 1024).unwrap();
        assert_eq!(s.files.len(), 1, "no case folding: notes.md rides");
        assert_eq!(stats.kept_home, 0);
    }

    #[test]
    fn sevralocal_covering_hub_files_is_a_scope_refusal() {
        for entry in ["DB.md\n", "assets.jsonl\n", "**\n"] {
            let t = tempfile::tempdir().unwrap();
            write(t.path(), "a.md", b"ride");
            write(t.path(), ".sevralocal", entry.as_bytes());
            match read_store(t.path().to_str().unwrap(), 1024) {
                Err(StoreError::Scope(msg)) => {
                    assert!(msg.contains("ride every push"), "{entry:?}: {msg}")
                }
                other => panic!(
                    "{entry:?} must refuse, got {:?}",
                    other.map(|_| "ok").map_err(|e| format!("{e:?}"))
                ),
            }
            // The unscoped walk (quarantine's full view) ignores the list.
            assert!(read_store_unscoped(t.path().to_str().unwrap(), 1024).is_ok());
        }
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

    #[cfg(unix)]
    #[test]
    fn external_file_symlink_is_refused_before_content_can_ride() {
        let store = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(store.path(), "DB.md", b"# safe");
        write(outside.path(), "credential.md", b"TOP SECRET");
        std::os::unix::fs::symlink(
            outside.path().join("credential.md"),
            store.path().join("leak.md"),
        )
        .unwrap();

        match read_store(store.path().to_str().unwrap(), 4096) {
            Err(StoreError::Io(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(error.to_string().contains("outside the store"));
                assert!(error.to_string().contains("leak.md"));
            }
            other => panic!("expected symlink refusal, got {:?}", other.map(|_| "ok")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn external_directory_symlink_is_refused_before_descending() {
        let store = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(store.path(), "DB.md", b"# safe");
        write(outside.path(), "credential.md", b"TOP SECRET");
        std::os::unix::fs::symlink(outside.path(), store.path().join("shared")).unwrap();

        match read_store(store.path().to_str().unwrap(), 4096) {
            Err(StoreError::Io(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(error.to_string().contains("shared"));
            }
            other => panic!("expected symlink refusal, got {:?}", other.map(|_| "ok")),
        }
    }

    // APFS rejects the invalid byte sequence at creation time; Linux filesystems
    // permit it, which is where the lossy-path regression can be exercised.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_store_entry_is_refused_instead_of_lossily_renamed() {
        use std::os::unix::ffi::OsStringExt;

        let store = tempfile::tempdir().unwrap();
        write(store.path(), "DB.md", b"# safe");
        let name = std::ffi::OsString::from_vec(b"bad-\xff.md".to_vec());
        fs::write(store.path().join(name), b"must not ride under another name").unwrap();

        match read_store(store.path().to_str().unwrap(), 4096) {
            Err(StoreError::Io(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                assert!(error.to_string().contains("not valid UTF-8"));
            }
            other => panic!("expected path refusal, got {:?}", other.map(|_| "ok")),
        }
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
