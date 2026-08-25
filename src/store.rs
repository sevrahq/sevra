//! Local db.md store read for `push`: walk a directory, collect `.md` files
//! (relative POSIX paths) + an optional `assets.jsonl`. Every directory and
//! file is opened from a held parent capability without following symlinks: a
//! cloned brain and a concurrent helper must never smuggle ~/.ssh or another
//! sibling tree into a push. Dotfiles are skipped. A `.sevralocal` at the store
//! root (see `crate::local`) keeps matching files home: excluded from the
//! collected store, counted separately in the stats.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
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

pub const MAX_PACK_FILES: usize = u16::MAX as usize;
pub const MAX_PACK_PATH_BYTES: usize = 1024;
pub const MAX_PACK_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
/// Worst-case exact size of the canonical ZIP32 profile: all permitted data,
/// maximum file count, and two copies of every maximum-length filename.
pub const MAX_CANONICAL_PACK_BYTES: u64 = MAX_PACK_UNCOMPRESSED_BYTES
    + MAX_PACK_FILES as u64 * (76 + 2 * MAX_PACK_PATH_BYTES as u64)
    + 22;

fn pack_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

fn valid_pack_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_PACK_PATH_BYTES
        && !path.starts_with('/')
        && !path.contains(['\0', '\\', ':'])
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Build the immutable whole-store ZIP used by the hub's large-brain path.
///
/// This is deliberately a tiny raw ZIP32 writer, not a library-default ZIP:
/// STORED members, fixed metadata, and no descriptors/extras/comments make
/// the bytes a cross-language protocol. The hub canonicalizes to this exact
/// profile before signing `pack_sha256`, so self-custody clients must produce
/// byte-identical bytes rather than merely an equivalent archive.
pub fn build_pack(store: &Store) -> std::io::Result<Vec<u8>> {
    let mut entries: Vec<(&str, &[u8])> = store
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_bytes()))
        .collect();
    if let Some(assets) = store.assets.as_deref() {
        entries.push(("assets.jsonl", assets.as_bytes()));
    }
    if entries.is_empty() {
        return Err(pack_error("a store pack must contain at least one file"));
    }
    if entries.len() > MAX_PACK_FILES {
        return Err(pack_error("store pack has too many files for ZIP32"));
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let mut total_data = 0u64;
    let mut previous: Option<&str> = None;
    for (path, bytes) in &entries {
        if !valid_pack_path(path) {
            return Err(pack_error(
                "store pack contains an unsafe or oversized path",
            ));
        }
        if previous == Some(path) {
            return Err(pack_error("store pack contains a duplicate path"));
        }
        previous = Some(path);
        total_data = total_data
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| pack_error("store pack size overflow"))?;
        if total_data > MAX_PACK_UNCOMPRESSED_BYTES || bytes.len() > u32::MAX as usize {
            return Err(pack_error(
                "store pack exceeds the uncompressed ZIP32 limit",
            ));
        }
    }

    let expected_len = total_data
        + entries
            .iter()
            .map(|(path, _)| 76 + 2 * path.len() as u64)
            .sum::<u64>()
        + 22;
    if expected_len > MAX_CANONICAL_PACK_BYTES || expected_len > u32::MAX as u64 {
        return Err(pack_error("canonical store pack exceeds the ZIP32 limit"));
    }
    let mut output = Vec::with_capacity(expected_len as usize);
    let mut records = Vec::with_capacity(entries.len());

    for (path, bytes) in &entries {
        let local_offset = u32::try_from(output.len())
            .map_err(|_| pack_error("canonical store pack offset exceeds ZIP32"))?;
        let size = u32::try_from(bytes.len())
            .map_err(|_| pack_error("store pack member exceeds ZIP32"))?;
        let crc32 = crc32fast::hash(bytes);
        let name = path.as_bytes();

        put_u32(&mut output, 0x0403_4b50);
        put_u16(&mut output, 20);
        put_u16(&mut output, 0x0800);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0x0021);
        put_u32(&mut output, crc32);
        put_u32(&mut output, size);
        put_u32(&mut output, size);
        put_u16(&mut output, name.len() as u16);
        put_u16(&mut output, 0);
        output.extend_from_slice(name);
        output.extend_from_slice(bytes);
        records.push((path, size, crc32, local_offset));
    }

    let central_offset = u32::try_from(output.len())
        .map_err(|_| pack_error("canonical central-directory offset exceeds ZIP32"))?;
    for (path, size, crc32, local_offset) in &records {
        let name = path.as_bytes();
        put_u32(&mut output, 0x0201_4b50);
        put_u16(&mut output, 0x0314);
        put_u16(&mut output, 20);
        put_u16(&mut output, 0x0800);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0x0021);
        put_u32(&mut output, *crc32);
        put_u32(&mut output, *size);
        put_u32(&mut output, *size);
        put_u16(&mut output, name.len() as u16);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0);
        put_u32(&mut output, 0o100600u32 << 16);
        put_u32(&mut output, *local_offset);
        output.extend_from_slice(name);
    }
    let central_size = u32::try_from(output.len() - central_offset as usize)
        .map_err(|_| pack_error("canonical central directory exceeds ZIP32"))?;
    let count = entries.len() as u16;
    put_u32(&mut output, 0x0605_4b50);
    put_u16(&mut output, 0);
    put_u16(&mut output, 0);
    put_u16(&mut output, count);
    put_u16(&mut output, count);
    put_u32(&mut output, central_size);
    put_u32(&mut output, central_offset);
    put_u16(&mut output, 0);
    debug_assert_eq!(output.len() as u64, expected_len);
    Ok(output)
}

/// How many of the largest files the walk keeps for limit-refusal reporting.
const LARGEST_TRACKED: usize = 10;

/// How many unaccounted paths the walk names in its report. Enough to act on;
/// the count is always exact regardless.
const UNACCOUNTED_SAMPLE: usize = 10;

/// A manifest longer than this is not read for declaration purposes. The push
/// enforces the real ceiling; this only bounds the walk's own memory.
const MANIFEST_SCAN_LINES: usize = 200_000;

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
    /// Files that reach the hub through NEITHER lane: not markdown (so not in
    /// the snapshot), not declared in `assets.jsonl` (so not in the asset
    /// lane), and not kept home on purpose. Binaries are supposed to travel as
    /// declared assets; an undeclared one silently never leaves the machine,
    /// which is the class the 2026-07-28 incident named — "0 assets" meant no
    /// manifest, and every binary stayed home while the push reported success.
    /// Counting them is what makes the skip say its own name.
    pub unaccounted: usize,
    /// A bounded sample of those paths, so a report can name files instead of
    /// only counting them. O(1) memory over any store size, like `largest`.
    pub unaccounted_sample: Vec<String>,
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

struct WalkState {
    store: Store,
    stats: WalkStats,
    /// Remaining read budget (max + 1). 0 = over the cap: stop reading
    /// content, keep walking so the stats stay honest.
    budget: u64,
}

fn walk(
    dir: &crate::safe_path::SafeDir,
    prefix: &str,
    st: &mut WalkState,
    scope: Option<&LocalScope>,
    declared: &BTreeSet<String>,
) -> std::io::Result<()> {
    for entry in dir.entries()? {
        let name = entry.name.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "refusing a store entry whose name is not valid UTF-8",
            )
        })?;
        if name.starts_with('.') {
            continue;
        }
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        match entry.kind {
            crate::safe_path::EntryKind::Symlink => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{rel}: refusing a symlink in the store"),
                ));
            }
            crate::safe_path::EntryKind::Directory => {
                let child = dir.open_dir(&entry.name).map_err(|error| {
                    std::io::Error::new(error.kind(), format!("{rel}: {error}"))
                })?;
                walk(&child, &rel, st, scope, declared)?;
            }
            crate::safe_path::EntryKind::File => {
                let counts = rel == "assets.jsonl" || rel.to_lowercase().ends_with(".md");
                if !counts {
                    // (`index.jsonl` never reaches the collected store on any
                    // path: it is not `.md` and only the ROOT `assets.jsonl`
                    // counts.)
                    //
                    // Skipping is correct — packs are markdown-only by design
                    // and binaries ride the asset lane — but skipping in
                    // SILENCE is not. A file declared in `assets.jsonl` is
                    // accounted for; one kept home was a deliberate choice;
                    // anything else would leave the machine's disk and never
                    // arrive anywhere, with the push still reporting success.
                    // Name it, and let the caller decide.
                    let deliberate = rel == "index.jsonl"
                        || rel.rsplit('/').next() == Some("index.jsonl")
                        || declared.contains(&rel)
                        || scope.is_some_and(|scope| scope.keeps_home(&rel));
                    if !deliberate {
                        st.stats.unaccounted += 1;
                        if st.stats.unaccounted_sample.len() < UNACCOUNTED_SAMPLE {
                            st.stats.unaccounted_sample.push(rel.clone());
                        }
                    }
                    continue;
                }
                if let Some(scope) = scope {
                    // Kept-home exclusions happen BEFORE any counting or
                    // opening: bytes that never ride are never touched.
                    if scope.keeps_home(&rel) {
                        st.stats.kept_home += 1;
                        continue;
                    }
                    if scope.active() && rel.rsplit('/').next() == Some("index.md") {
                        st.stats.catalogs_kept += 1;
                        continue;
                    }
                }
                let mut file = dir.open_file(&entry.name).map_err(|error| {
                    std::io::Error::new(error.kind(), format!("{rel}: {error}"))
                })?;
                let metadata_len = file.metadata()?.len();
                st.stats.files += 1;
                if st.budget == 0 {
                    st.stats.bytes = st.stats.bytes.saturating_add(metadata_len);
                    note_largest(&mut st.stats.largest, &rel, metadata_len);
                    continue;
                }

                // Metadata and content come from the same held descriptor.
                // Taking at most remaining+1 keeps a concurrently grown file
                // from becoming an unbounded allocation.
                let read_cap = st.budget;
                let mut bytes = Vec::with_capacity(
                    usize::try_from(metadata_len.min(read_cap).min(1024 * 1024)).unwrap_or(0),
                );
                Read::by_ref(&mut file)
                    .take(read_cap)
                    .read_to_end(&mut bytes)
                    .map_err(|e| std::io::Error::other(format!("{rel}: {e}")))?;
                let actual_len = bytes.len() as u64;
                if actual_len >= read_cap {
                    st.budget = 0;
                    let counted = metadata_len.max(actual_len);
                    st.stats.bytes = st.stats.bytes.saturating_add(counted);
                    note_largest(&mut st.stats.largest, &rel, counted);
                    continue;
                }
                st.budget -= actual_len;
                st.stats.bytes = st.stats.bytes.saturating_add(actual_len);
                note_largest(&mut st.stats.largest, &rel, actual_len);
                let content = String::from_utf8(bytes)
                    .map_err(|e| std::io::Error::other(format!("{rel}: {e}")))?;
                if rel == "assets.jsonl" {
                    st.store.assets = Some(content);
                } else {
                    st.store.files.push(StoreFile { path: rel, content });
                }
            }
            crate::safe_path::EntryKind::Other => {}
        }
    }
    Ok(())
}

/// Read the store as a push would carry it: the walk honors `.sevralocal`
/// (kept-home files and, when the scope is active, derived catalogs are
/// excluded and counted in the stats), refusing once raw riding bytes exceed
/// `max_bytes` — a store whose raw file bytes exceed the cap cannot fit
/// under it as JSON either (escaping only grows), so a multi-GB
/// vault is never read into memory before a post-hoc check. On the cap
/// refusal the walk continues without reading, so `StoreError::OverCap`
/// carries the store's true totals and its largest files.
/// Store-relative paths declared in the root `assets.jsonl`.
///
/// Read leniently and on purpose: a malformed or absent manifest is the push's
/// error to report, never the walk's to fail on. Anything unparseable yields
/// no declarations, so the walk reports MORE files as unaccounted, never
/// fewer — the honest direction for a warning whose job is to break silence.
fn declared_asset_paths(dir: &str) -> BTreeSet<String> {
    let mut declared = BTreeSet::new();
    let Ok(bytes) = fs::read(Path::new(dir).join("assets.jsonl")) else {
        return declared;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return declared;
    };
    for line in text.lines().take(MANIFEST_SCAN_LINES) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(path) = value.get("path").and_then(|p| p.as_str()) {
            declared.insert(path.to_string());
        }
    }
    declared
}

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
    let root_real = fs::canonicalize(Path::new(dir)).map_err(StoreError::Io)?;
    let root = crate::safe_path::SafeDir::open(&root_real).map_err(StoreError::Io)?;
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
            unaccounted: 0,
            unaccounted_sample: Vec::new(),
        },
        // budget hits zero exactly when the running total EXCEEDS max_bytes —
        // a store of exactly max_bytes raw bytes is still allowed through to
        // the exact JSON-size check in `push`.
        budget: max_bytes.saturating_add(1),
    };
    match walk(&root, "", &mut st, scope, &declared_asset_paths(dir)) {
        Ok(()) if st.budget == 0 => Err(StoreError::OverCap(st.stats)),
        Ok(()) => Ok((st.store, st.stats)),
        Err(e) => Err(StoreError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Cursor;

    fn write(dir: &std::path::Path, rel: &str, content: &[u8]) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    #[test]
    fn an_undeclared_binary_is_named_rather_than_silently_skipped() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"alpha");
        write(t.path(), "sources/report.pdf", b"%PDF-1.4");
        write(t.path(), "sources/photo.png", b"\x89PNG");

        let (store, stats) = read_store(t.path().to_str().unwrap(), 1 << 20).unwrap();

        // The snapshot is unchanged — packs stay markdown-only.
        assert_eq!(
            store
                .files
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            ["a.md"]
        );
        // …but the push can no longer claim success in silence about them.
        assert_eq!(stats.unaccounted, 2);
        let mut sample = stats.unaccounted_sample.clone();
        sample.sort();
        assert_eq!(sample, ["sources/photo.png", "sources/report.pdf"]);
    }

    #[test]
    fn a_declared_asset_is_accounted_for_and_never_warned_about() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"alpha");
        write(t.path(), "sources/report.pdf", b"%PDF-1.4");
        write(t.path(), "sources/photo.png", b"\x89PNG");
        // Only the PDF is declared; the PNG is not.
        write(
            t.path(),
            "assets.jsonl",
            br#"{"path":"sources/report.pdf","sha256":"ab","bytes":8}"#,
        );

        let (_, stats) = read_store(t.path().to_str().unwrap(), 1 << 20).unwrap();

        assert_eq!(stats.unaccounted, 1);
        assert_eq!(stats.unaccounted_sample, ["sources/photo.png"]);
    }

    #[test]
    fn a_malformed_manifest_warns_more_never_less() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"alpha");
        write(t.path(), "sources/report.pdf", b"%PDF-1.4");
        write(t.path(), "assets.jsonl", b"this is not jsonl {{{");

        // The walk does not fail on it — that is the push's error to report —
        // and it declares nothing, so the file is still named.
        let (_, stats) = read_store(t.path().to_str().unwrap(), 1 << 20).unwrap();
        assert_eq!(stats.unaccounted, 1);
    }

    #[test]
    fn deliberate_absences_are_not_warnings() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"alpha");
        // A derived catalog sidecar never rides on any path.
        write(t.path(), "index.jsonl", b"{}");
        write(t.path(), "records/index.jsonl", b"{}");
        // A file the owner deliberately kept home is a choice, not a surprise.
        write(t.path(), "sources/secret.pem", b"key");
        write(t.path(), ".sevralocal", b"sources/secret.pem\n");

        let (_, stats) = read_store(t.path().to_str().unwrap(), 1 << 20).unwrap();

        assert_eq!(stats.unaccounted, 0);
        assert!(stats.unaccounted_sample.is_empty());
    }

    #[test]
    fn the_named_sample_is_bounded_while_the_count_stays_exact() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", b"alpha");
        for i in 0..25 {
            write(t.path(), &format!("sources/blob{i}.bin"), b"x");
        }

        let (_, stats) = read_store(t.path().to_str().unwrap(), 1 << 20).unwrap();

        assert_eq!(stats.unaccounted, 25);
        assert_eq!(stats.unaccounted_sample.len(), UNACCOUNTED_SAMPLE);
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
    fn an_internal_directory_symlink_is_refused_too() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a/note.md", b"hi");
        std::os::unix::fs::symlink(t.path(), t.path().join("a/loop")).unwrap();
        match read_store(t.path().to_str().unwrap(), 4096) {
            Err(StoreError::Io(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(error.to_string().contains("a/loop"));
            }
            other => panic!("expected symlink refusal, got {:?}", other.map(|_| "ok")),
        }
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
                assert!(error.to_string().contains("symlink in the store"));
                assert!(error.to_string().contains("leak.md"));
            }
            other => panic!("expected symlink refusal, got {:?}", other.map(|_| "ok")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_leaf_swap_cannot_make_external_bytes_ride() {
        use std::sync::{Arc, Barrier};

        let store = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(store.path(), "DB.md", b"# safe");
        write(store.path(), "race-held-handle.md", b"inside");
        write(
            outside.path(),
            "private.md",
            b"EXTERNAL-CONTENT-MUST-NOT-RIDE",
        );

        let barrier = Arc::new(Barrier::new(2));
        crate::safe_path::set_test_before_open(
            std::ffi::OsString::from("race-held-handle.md"),
            Arc::clone(&barrier),
        );
        let store_path = store.path().to_path_buf();
        let reader = std::thread::spawn(move || read_store(store_path.to_str().unwrap(), 4096));

        barrier.wait();
        fs::rename(
            store.path().join("race-held-handle.md"),
            store.path().join("parked.md"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("private.md"),
            store.path().join("race-held-handle.md"),
        )
        .unwrap();
        barrier.wait();

        match reader.join().unwrap() {
            Err(StoreError::Io(error)) => {
                let message = error.to_string();
                assert!(message.contains("race-held-handle.md"));
                assert!(!message.contains("EXTERNAL-CONTENT-MUST-NOT-RIDE"));
            }
            other => panic!(
                "the raced symlink must be refused, got {:?}",
                other.map(|_| "ok")
            ),
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
        let first = archive.by_index(0).unwrap();
        assert_eq!(first.name(), "a.md");
        assert_eq!(first.compression(), zip::CompressionMethod::Stored);
        assert_eq!(first.unix_mode(), Some(0o100600));
        drop(first);
        assert_eq!(archive.by_index(1).unwrap().name(), "assets.jsonl");
        assert_eq!(archive.by_index(2).unwrap().name(), "z.md");
    }

    #[test]
    fn canonical_pack_matches_the_cross_language_golden_vector() {
        let store = Store {
            files: vec![
                StoreFile {
                    path: "records/a.md".to_string(),
                    content: "alpha\n".to_string(),
                },
                StoreFile {
                    path: "DB.md".to_string(),
                    content: "# db\n".to_string(),
                },
            ],
            assets: None,
        };
        let bytes = build_pack(&store).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "972fb2045becaa21588baaf4b349e62a430687fa2c21167b53f4ca0efa6c9408"
        );
        assert_eq!(bytes.len(), 219);
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        assert_eq!(archive.len(), 2);
        let mut db = String::new();
        archive
            .by_name("DB.md")
            .unwrap()
            .read_to_string(&mut db)
            .unwrap();
        assert_eq!(db, "# db\n");
    }

    #[test]
    fn canonical_pack_rejects_non_protocol_shapes_before_writing() {
        assert!(build_pack(&Store {
            files: Vec::new(),
            assets: None,
        })
        .unwrap_err()
        .to_string()
        .contains("at least one"));
        assert!(build_pack(&Store {
            files: vec![
                StoreFile {
                    path: "a.md".into(),
                    content: "one".into(),
                },
                StoreFile {
                    path: "a.md".into(),
                    content: "two".into(),
                },
            ],
            assets: None,
        })
        .unwrap_err()
        .to_string()
        .contains("duplicate"));
        let exact_path = format!("{}.md", "a".repeat(MAX_PACK_PATH_BYTES - 3));
        assert_eq!(exact_path.len(), MAX_PACK_PATH_BYTES);
        assert!(build_pack(&Store {
            files: vec![StoreFile {
                path: exact_path,
                content: String::new(),
            }],
            assets: None,
        })
        .is_ok());
        let long_path = format!("{}.md", "a".repeat(MAX_PACK_PATH_BYTES));
        assert!(long_path.len() > MAX_PACK_PATH_BYTES);
        assert!(build_pack(&Store {
            files: vec![StoreFile {
                path: long_path,
                content: String::new(),
            }],
            assets: None,
        })
        .unwrap_err()
        .to_string()
        .contains("oversized"));
    }

    #[test]
    fn canonical_zip32_file_count_boundary_is_exact() {
        let files = (0..MAX_PACK_FILES)
            .map(|index| StoreFile {
                path: format!("records/{index:05}.md"),
                content: String::new(),
            })
            .collect();
        let bytes = build_pack(&Store {
            files,
            assets: None,
        })
        .expect("65,535 file members fit the canonical ZIP32 profile");
        assert_eq!(
            &bytes[bytes.len() - 12..bytes.len() - 10],
            &u16::MAX.to_le_bytes(),
            "EOCD carries the exact maximum entry count without ZIP64"
        );

        let too_many = (0..=MAX_PACK_FILES)
            .map(|index| StoreFile {
                path: format!("records/{index:05}.md"),
                content: String::new(),
            })
            .collect();
        assert!(build_pack(&Store {
            files: too_many,
            assets: None,
        })
        .unwrap_err()
        .to_string()
        .contains("too many files"));
    }
}
