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

fn rel_posix(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn walk(root: &Path, dir: &Path, visited: &mut HashSet<std::path::PathBuf>, store: &mut Store) -> std::io::Result<()> {
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
            walk(root, &full, visited, store)?;
        } else if meta.is_file() {
            let rel = rel_posix(root, &full);
            if rel == "assets.jsonl" {
                store.assets = Some(fs::read_to_string(&full)?);
            } else if rel.to_lowercase().ends_with(".md") {
                store.files.push(StoreFile {
                    path: rel,
                    content: fs::read_to_string(&full)?,
                });
            }
        }
    }
    Ok(())
}

pub fn read_store(dir: &str) -> std::io::Result<Store> {
    let root = Path::new(dir);
    let mut store = Store {
        files: Vec::new(),
        assets: None,
    };
    let mut visited = HashSet::new();
    visited.insert(fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()));
    walk(root, root, &mut visited, &mut store)?;
    Ok(store)
}
