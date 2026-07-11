//! Local db.md store read for `push`: walk a directory, collect `.md` files
//! (relative POSIX paths) + an optional `assets.jsonl`, following symlinks with
//! cycle protection (Obsidian-style vaults symlink shared folders), skipping
//! dotfiles. Mirrors the TS CLI's readStoreFiles.

use std::collections::HashSet;
use std::fs;
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

/// Sentinel error text for the size-cap refusal — one definition, so the
/// raiser in `walk` and the matcher in `read_store` can never drift apart.
const CAP_EXCEEDED: &str = "push cap exceeded";

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

fn walk(
    root: &Path,
    dir: &Path,
    visited: &mut HashSet<std::path::PathBuf>,
    store: &mut Store,
    budget: &mut u64,
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
            walk(root, &full, visited, store, budget)?;
        } else if meta.is_file() {
            let rel = rel_posix(root, &full);
            let counts = rel == "assets.jsonl" || rel.to_lowercase().ends_with(".md");
            if counts {
                // Size-gate BEFORE reading: past the budget, stop touching disk.
                *budget = budget.saturating_sub(meta.len());
                if *budget == 0 {
                    return Err(std::io::Error::other(CAP_EXCEEDED));
                }
            }
            if rel == "assets.jsonl" {
                store.assets = Some(read_named(&full, &rel)?);
            } else if counts {
                let content = read_named(&full, &rel)?;
                store.files.push(StoreFile { path: rel, content });
            }
        }
    }
    Ok(())
}

/// Read the store, refusing early once raw bytes exceed `max_bytes` — a
/// store whose raw file bytes exceed the cap cannot fit under it as JSON
/// either (escaping only grows), so a symlinked multi-GB vault is never read
/// into memory before a post-hoc check. Err(None) = cap exceeded.
pub fn read_store(dir: &str, max_bytes: u64) -> Result<Store, Option<std::io::Error>> {
    let root = Path::new(dir);
    let mut store = Store {
        files: Vec::new(),
        assets: None,
    };
    let mut visited = HashSet::new();
    visited.insert(fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()));
    // budget hits zero exactly when the running total EXCEEDS max_bytes —
    // a store of exactly max_bytes raw bytes is still allowed through to the
    // exact JSON-size check in `push`.
    let mut budget = max_bytes.saturating_add(1);
    match walk(root, root, &mut visited, &mut store, &mut budget) {
        Ok(()) => Ok(store),
        Err(e) if e.to_string() == CAP_EXCEEDED => Err(None),
        Err(e) => Err(Some(e)),
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
        let s = read_store(t.path().to_str().unwrap(), 1024).unwrap();
        let mut paths: Vec<_> = s.files.iter().map(|f| f.path.clone()).collect();
        paths.sort();
        assert_eq!(paths, ["a.md", "sub/b.MD"]);
        assert_eq!(s.assets.as_deref(), Some("{}"));
    }

    #[test]
    fn cap_allows_exactly_max_refuses_one_more() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a.md", &[b'x'; 100]);
        assert!(read_store(t.path().to_str().unwrap(), 100).is_ok());
        write(t.path(), "b.md", b"y");
        match read_store(t.path().to_str().unwrap(), 100) {
            Err(None) => {} // cap refusal, before reading past it
            other => panic!("expected cap refusal, got {:?}", other.map(|_| "ok")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cycle_terminates_and_dedupes() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a/note.md", b"hi");
        std::os::unix::fs::symlink(t.path(), t.path().join("a/loop")).unwrap();
        let s = read_store(t.path().to_str().unwrap(), 4096).unwrap();
        assert_eq!(s.files.len(), 1, "the cycled file must be collected once");
    }

    #[test]
    fn non_utf8_read_error_names_the_file() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "bad.md", &[0xff, 0xfe, b'x']);
        match read_store(t.path().to_str().unwrap(), 4096) {
            Err(Some(e)) => assert!(e.to_string().contains("bad.md"), "got: {e}"),
            other => panic!("expected named read error, got {:?}", other.map(|_| "ok")),
        }
    }
}
