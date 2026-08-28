//! Recovery closures for a hosted brain.
//!
//! A db.md store remains the semantic authority. A package profile inside the
//! store names the path-dependent companion files needed to operate it. This
//! module snapshots those files as immutable, content-addressed db.md assets,
//! records an exact manifest in the brain, and then uses the ordinary signed
//! Link.md v2 commit. No second transport, mutable archive, or machine image is
//! introduced: unchanged object hashes do not upload again.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use globset::GlobBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::commands::{self, PushOptions};
use crate::config::Config;
use crate::hub::{ensure_ok, request};
use crate::output::{fail, out_layout, terminal_safe};
use crate::safe_path::{self, EntryKind, SafeDir};

const PROFILE_RECORD: &str = "records/operational/sevra-package-profile.md";
const SNAPSHOT_RECORD: &str = "records/operational/sevra-package-snapshot.md";
const OBJECT_PREFIX: &str = "sources/sevra-package/objects";
const PROFILE_FENCE: &str = "sevra-package-v1";
const SNAPSHOT_FENCE: &str = "sevra-package-snapshot-v1";
const CHECKOUT_RECEIPT: &str = ".sevra-package-v1.json";
const PULL_JOURNAL: &str = ".sevra-package-pull-v1.json";
const PACKAGE_LOCK: &str = ".sevra-package.lock";
const RECOVERY_PREFIX: &str = ".sevra-package-recovery-";
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILES: usize = 65_535;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageConfig {
    version: u8,
    profiles: BTreeMap<String, ProfileSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProfileSpec {
    include: Vec<IncludeSpec>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    allow_secret_named_paths: Vec<String>,
    #[serde(default)]
    allow_unscanned_binary_paths: Vec<String>,
    #[serde(default)]
    dependencies: Vec<DependencySpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IncludeSpec {
    path: String,
    #[serde(default)]
    allow_unscanned_binary: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DependencySpec {
    id: String,
    kind: String,
    #[serde(default)]
    required: bool,
    #[serde(default = "default_dependency_impact")]
    impact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    locator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<PathVerification>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
enum PathVerification {
    RegularFile {
        #[serde(default)]
        allow_empty: bool,
    },
    Directory {
        #[serde(default)]
        allow_empty: bool,
        #[serde(default)]
        required: Vec<String>,
    },
    SevralocalClosure {
        policy_sha256: String,
        #[serde(default)]
        minimum_entries: usize,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
enum SnapshotEntry {
    File {
        path: String,
        sha256: String,
        bytes: u64,
        mode: u32,
        asset: String,
        unscanned_binary: bool,
    },
    Symlink {
        path: String,
        target: String,
        target_kind: String,
    },
}

impl SnapshotEntry {
    fn path(&self) -> &str {
        match self {
            Self::File { path, .. } | Self::Symlink { path, .. } => path,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DependencyReceipt {
    id: String,
    kind: String,
    required: bool,
    #[serde(default = "default_dependency_impact")]
    impact: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<PathVerification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotCore {
    version: u8,
    profile: String,
    profile_sha256: String,
    store: String,
    entries: Vec<SnapshotEntry>,
    dependencies: Vec<DependencyReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    projection: Option<ProjectionManifest>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProjectionManifest {
    version: u8,
    algorithm: String,
    path_hashes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotEnvelope {
    version: u8,
    snapshot_root: String,
    created_at: String,
    core: SnapshotCore,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackageCheckout {
    version: u8,
    brain: String,
    profile: String,
    snapshot_root: String,
    entries: Vec<SnapshotEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackagePullOperation {
    path: String,
    old: Option<SnapshotEntry>,
    new: Option<SnapshotEntry>,
    backup: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackagePullJournal {
    version: u8,
    recovery_dir: String,
    previous: PackageCheckout,
    next: PackageCheckout,
    operations: Vec<PackagePullOperation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageReport {
    pub profile: String,
    pub snapshot_root: String,
    pub files: usize,
    pub symlinks: usize,
    pub objects: usize,
    pub bytes: u64,
    pub changed: bool,
    pub unscanned_files: usize,
    pub dependencies_resolved: usize,
    pub dependencies_unresolved: usize,
    pub semantic_unresolved_dependencies: Vec<String>,
    pub brain_complete: bool,
    pub operational_ready: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyReport {
    profile: String,
    snapshot_root: String,
    files: usize,
    symlinks: usize,
    objects: usize,
    bytes: u64,
    missing: Vec<String>,
    corrupt: Vec<String>,
    unresolved_dependencies: Vec<String>,
    required_unresolved_dependencies: Vec<String>,
    semantic_unresolved_dependencies: Vec<String>,
    brain_complete: bool,
    operational_ready: bool,
    complete: bool,
}

fn default_dependency_impact() -> String {
    "operational".to_string()
}

struct Workspace {
    root: PathBuf,
    store: PathBuf,
    store_rel: String,
}

#[derive(Default)]
struct Collected {
    entries: BTreeMap<String, SnapshotEntry>,
    objects: BTreeMap<String, Vec<u8>>,
    bytes: u64,
    unscanned: usize,
}

fn progress_heartbeat(
    initial: &str,
    ongoing: &str,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    eprintln!("{initial}");
    let (done, wait) = std::sync::mpsc::channel::<()>();
    let ongoing = ongoing.to_string();
    let thread = std::thread::spawn(move || loop {
        match wait.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => eprintln!("{ongoing}"),
        }
    });
    (done, thread)
}

fn stop_progress(done: std::sync::mpsc::Sender<()>, thread: std::thread::JoinHandle<()>) {
    let _ = done.send(());
    let _ = thread.join();
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot encode canonical package state: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn normalize_rel(raw: &str, what: &str) -> Result<String, String> {
    if raw.is_empty() || raw.contains('\0') || raw.contains('\\') {
        return Err(format!("{what} must be a non-empty portable relative path"));
    }
    let mut parts = Vec::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| format!("{what} is not portable UTF-8"))?;
                if part == "." || part.is_empty() {
                    return Err(format!("{what} is not normalized"));
                }
                parts.push(part);
            }
            _ => return Err(format!("{what} must be normalized and relative")),
        }
    }
    if parts.is_empty() {
        return Err(format!("{what} has no file name"));
    }
    Ok(parts.join("/"))
}

fn valid_name(raw: &str, what: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.len() > 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || raw.starts_with('-')
        || raw.ends_with('-')
    {
        return Err(format!(
            "{what} must use lowercase letters, numbers, and interior hyphens (at most 64 characters)"
        ));
    }
    Ok(())
}

fn is_canonical_brain_id(raw: &str) -> bool {
    raw.len() == 26
        && raw.bytes().all(|byte| {
            byte.is_ascii_digit()
                || byte.is_ascii_lowercase() && !matches!(byte, b'i' | b'l' | b'o' | b'u')
        })
}

fn discover_workspace(path: &str) -> Result<Workspace, String> {
    let root = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve workspace {path}: {error}"))?;
    if !root.is_dir() {
        return Err("package workspace is not a directory".into());
    }
    let store = root.join("db");
    if !store.join("DB.md").is_file() {
        return Err(
            "package workspace must contain a db.md store at db/ (plain brain clone/push still accepts a store directly)"
                .into(),
        );
    }
    Ok(Workspace {
        root,
        store,
        store_rel: "db".into(),
    })
}

fn extract_fenced_json<T: for<'de> Deserialize<'de>>(
    markdown: &[u8],
    fence: &str,
) -> Result<T, String> {
    if markdown.len() > 4 * 1024 * 1024 {
        return Err(format!("{fence} record is oversized"));
    }
    let text = std::str::from_utf8(markdown)
        .map_err(|_| format!("{fence} record is not UTF-8"))?
        .replace("\r\n", "\n");
    let opening = format!("```{fence}\n");
    let mut starts = text.match_indices(&opening);
    let (opening_start, _) = starts
        .next()
        .ok_or_else(|| format!("record has no `{fence}` fenced JSON block"))?;
    if starts.next().is_some() {
        return Err(format!("record has more than one `{fence}` block"));
    }
    let body_start = opening_start + opening.len();
    let rest = &text[body_start..];
    let body_end = rest
        .find("\n```\n")
        .or_else(|| rest.strip_suffix("\n```").map(|body| body.len()))
        .ok_or_else(|| format!("`{fence}` block is not closed on its own line"))?;
    serde_json::from_str(&rest[..body_end])
        .map_err(|error| format!("invalid `{fence}` JSON: {error}"))
}

fn read_profile(workspace: &Workspace, name: &str) -> Result<ProfileSpec, String> {
    valid_name(name, "profile name")?;
    let bytes = safe_path::read_regular(&workspace.store, PROFILE_RECORD)
        .map_err(|error| format!("cannot read package profile: {error}"))?
        .ok_or_else(|| {
            format!(
                "brain has no package profile; create {PROFILE_RECORD} with one `{PROFILE_FENCE}` JSON block"
            )
        })?;
    let config: PackageConfig = extract_fenced_json(&bytes, PROFILE_FENCE)?;
    if config.version != 1 {
        return Err(format!(
            "unsupported package profile version {} (expected 1)",
            config.version
        ));
    }
    let profile = config
        .profiles
        .into_iter()
        .find_map(|(candidate, spec)| (candidate == name).then_some(spec))
        .ok_or_else(|| format!("package profile `{name}` is not defined"))?;
    validate_profile(&profile)?;
    Ok(profile)
}

fn validate_profile(profile: &ProfileSpec) -> Result<(), String> {
    if profile.include.is_empty() {
        return Err("package profile includes no companion paths".into());
    }
    let mut seen = BTreeSet::new();
    for include in &profile.include {
        let path = normalize_rel(&include.path, "included path")?;
        if !seen.insert(path) {
            return Err("package profile contains a duplicate included path".into());
        }
    }
    for exclude in &profile.exclude {
        normalize_rel(exclude, "excluded path")?;
    }
    for allowed in &profile.allow_secret_named_paths {
        normalize_rel(allowed, "secret-named exception")?;
    }
    let mut binary_paths = BTreeSet::new();
    for allowed in &profile.allow_unscanned_binary_paths {
        let path = normalize_rel(allowed, "binary exception")?;
        if !binary_paths.insert(path.clone()) {
            return Err(format!("duplicate binary exception `{path}`"));
        }
        if generated_cache_path(&path) {
            return Err(format!(
                "binary exception `{path}` selects generated cache content"
            ));
        }
        if !path_selected(profile, &path) || excluded(&path, &profile.exclude) {
            return Err(format!(
                "binary exception `{path}` is not inside the selected package closure"
            ));
        }
    }
    let mut dependency_ids = BTreeSet::new();
    for dependency in &profile.dependencies {
        valid_name(&dependency.id, "dependency id")?;
        if !dependency_ids.insert(&dependency.id) {
            return Err(format!("duplicate package dependency `{}`", dependency.id));
        }
        if !matches!(dependency.impact.as_str(), "semantic" | "operational") {
            return Err(format!(
                "dependency `{}` impact must be `semantic` or `operational`",
                dependency.id
            ));
        }
        match dependency.kind.as_str() {
            "git" => {
                if dependency.path.is_none()
                    || dependency.name.is_some()
                    || dependency.locator.is_some()
                    || dependency.local_path.is_some()
                    || dependency.verification.is_some()
                {
                    return Err(format!(
                        "git dependency `{}` requires path and forbids name, local_path, and verification",
                        dependency.id
                    ));
                }
            }
            "path" => {
                if dependency.path.is_none()
                    || dependency.name.is_some()
                    || dependency.locator.is_some()
                    || dependency.remote.is_some()
                    || dependency.local_path.is_some()
                {
                    return Err(format!("path dependency `{}` requires path", dependency.id));
                }
            }
            "secret" => {
                if dependency.name.is_none()
                    || dependency.path.is_some()
                    || dependency.locator.is_some()
                    || dependency.remote.is_some()
                {
                    return Err(format!(
                        "secret dependency `{}` requires name and forbids path",
                        dependency.id
                    ));
                }
                if dependency.local_path.is_none() && dependency.verification.is_some() {
                    return Err(format!(
                        "secret dependency `{}` cannot verify an absent local_path",
                        dependency.id
                    ));
                }
            }
            "live" | "external" => {
                if dependency.locator.is_none()
                    || dependency.path.is_some()
                    || dependency.name.is_some()
                    || dependency.remote.is_some()
                    || dependency.local_path.is_some()
                    || dependency.verification.is_some()
                {
                    return Err(format!(
                        "{} dependency `{}` requires only a locator",
                        dependency.kind, dependency.id
                    ));
                }
            }
            other => {
                return Err(format!(
                    "dependency `{}` has unsupported kind `{other}`",
                    dependency.id
                ))
            }
        }
        if let Some(path) = &dependency.path {
            if path != "." {
                normalize_rel(path, "dependency path")?;
            }
        }
        if let Some(path) = &dependency.local_path {
            normalize_rel(path, "dependency local path")?;
        }
        if let Some(verification) = &dependency.verification {
            validate_path_verification(dependency, verification)?;
        }
    }
    Ok(())
}

fn validate_path_verification(
    dependency: &DependencySpec,
    verification: &PathVerification,
) -> Result<(), String> {
    match verification {
        PathVerification::RegularFile { .. } => Ok(()),
        PathVerification::Directory { required, .. } => {
            let mut seen = BTreeSet::new();
            for child in required {
                let child = normalize_rel(child, "dependency required child")?;
                if !seen.insert(child.clone()) {
                    return Err(format!(
                        "dependency `{}` repeats required child `{child}`",
                        dependency.id
                    ));
                }
            }
            Ok(())
        }
        PathVerification::SevralocalClosure {
            policy_sha256,
            minimum_entries,
        } => {
            if dependency.kind != "path"
                || !dependency
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("/.sevralocal"))
                || policy_sha256.len() != 64
                || !policy_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || *minimum_entries == 0
            {
                return Err(format!(
                    "dependency `{}` has an invalid sevralocal_closure verification",
                    dependency.id
                ));
            }
            Ok(())
        }
    }
}

fn path_selected(profile: &ProfileSpec, path: &str) -> bool {
    profile
        .include
        .iter()
        .any(|include| path == include.path || path.starts_with(&format!("{}/", include.path)))
}

fn excluded(path: &str, excludes: &[String]) -> bool {
    excludes
        .iter()
        .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
}

fn generated_cache_path(path: &str) -> bool {
    path.split('/').any(|component| {
        matches!(
            component,
            "__pycache__"
                | "node_modules"
                | ".pytest_cache"
                | ".mypy_cache"
                | ".ruff_cache"
                | ".DS_Store"
        ) || component.ends_with(".pyc")
            || component.ends_with(".pyo")
    })
}

fn lexical_symlink_target(path: &str, raw_target: &str) -> Result<String, String> {
    if raw_target.is_empty() || raw_target.contains('\0') || raw_target.contains('\\') {
        return Err(format!(
            "symlink {path} has an invalid or non-portable target"
        ));
    }
    let mut result: Vec<&str> = path.split('/').collect();
    result.pop();
    for component in Path::new(raw_target).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if result.pop().is_none() {
                    return Err(format!("symlink {path} escapes the package workspace"));
                }
            }
            Component::Normal(part) => result.push(
                part.to_str()
                    .ok_or_else(|| format!("symlink {path} target is not UTF-8"))?,
            ),
            _ => return Err(format!("symlink {path} has an absolute target")),
        }
    }
    if result.is_empty() {
        return Err(format!("symlink {path} resolves to the workspace root"));
    }
    Ok(result.join("/"))
}

fn validate_symlink_closure(entries: &[SnapshotEntry]) -> Result<(), String> {
    let paths = entries
        .iter()
        .map(|entry| entry.path().to_string())
        .collect::<BTreeSet<_>>();
    for entry in entries {
        let SnapshotEntry::Symlink {
            path,
            target,
            target_kind,
        } = entry
        else {
            continue;
        };
        let resolved = lexical_symlink_target(path, target)?;
        let packaged = match target_kind.as_str() {
            "file" => paths.contains(&resolved),
            "directory" => paths
                .iter()
                .any(|candidate| candidate.starts_with(&format!("{resolved}/"))),
            _ => false,
        };
        if !packaged {
            return Err(format!(
                "symlink {path} targets {resolved}, which is outside the selected package closure"
            ));
        }
    }
    Ok(())
}

fn scan_companion(
    path: &str,
    bytes: &[u8],
    allow_named: bool,
    allow_binary: bool,
) -> Result<bool, String> {
    if !allow_named {
        if let Some(hit) = crate::scan::scan_path(path).first() {
            return Err(format!(
                "package refused secret-shaped companion path {} ({})",
                terminal_safe(&hit.path),
                hit.kind
            ));
        }
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            if let Some(hit) = crate::scan::scan_content(path, text).first() {
                return Err(format!(
                    "package refused secret-shaped content in {} ({})",
                    terminal_safe(&hit.path),
                    hit.kind
                ));
            }
            Ok(false)
        }
        Err(_) if allow_binary => Ok(true),
        Err(_) => Err(format!(
            "package companion {path} is not UTF-8; set allow_unscanned_binary only for a reviewed binary include"
        )),
    }
}

#[cfg(unix)]
fn portable_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o111 != 0 {
        0o755
    } else {
        0o644
    }
}

#[cfg(not(unix))]
fn portable_mode(_metadata: &fs::Metadata) -> u32 {
    0o644
}

fn collect_file(
    dir: &SafeDir,
    leaf: &OsStr,
    path: &str,
    allow_binary: bool,
    allowed_names: &BTreeSet<String>,
    collected: &mut Collected,
) -> Result<(), String> {
    if generated_cache_path(path) {
        return Err(format!(
            "package refuses generated cache companion {path}; exclude it from the profile"
        ));
    }
    if collected.entries.len() >= MAX_FILES {
        return Err(format!("package exceeds the {MAX_FILES}-entry limit"));
    }
    let mut file = dir
        .open_file(leaf)
        .map_err(|error| format!("cannot securely open companion {path}: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect companion {path}: {error}"))?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err(format!(
            "package companion {path} is {} bytes; one file is capped at {MAX_FILE_BYTES}",
            metadata.len()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read companion {path}: {error}"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "package companion {path} grew beyond the per-file limit"
        ));
    }
    collected.bytes = collected
        .bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| "package byte count overflowed".to_string())?;
    if collected.bytes > MAX_TOTAL_BYTES {
        return Err(format!(
            "package exceeds the {MAX_TOTAL_BYTES}-byte total limit"
        ));
    }
    let unscanned = scan_companion(path, &bytes, allowed_names.contains(path), allow_binary)?;
    if unscanned {
        collected.unscanned += 1;
    }
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let asset = format!("{OBJECT_PREFIX}/{hash}.blob");
    let byte_len = bytes.len() as u64;
    collected.objects.entry(hash.clone()).or_insert(bytes);
    let prior = collected.entries.insert(
        path.to_string(),
        SnapshotEntry::File {
            path: path.to_string(),
            sha256: hash,
            bytes: byte_len,
            mode: portable_mode(&metadata),
            asset,
            unscanned_binary: unscanned,
        },
    );
    if prior.is_some() {
        return Err(format!("package profile selects {path} more than once"));
    }
    Ok(())
}

fn collect_symlink(
    workspace: &Workspace,
    dir: &SafeDir,
    leaf: &OsStr,
    path: &str,
    allowed_names: &BTreeSet<String>,
    collected: &mut Collected,
) -> Result<(), String> {
    if collected.entries.len() >= MAX_FILES {
        return Err(format!("package exceeds the {MAX_FILES}-entry limit"));
    }
    if !allowed_names.contains(path) {
        if let Some(hit) = crate::scan::scan_path(path).first() {
            return Err(format!(
                "package refused secret-shaped symlink path {} ({})",
                terminal_safe(&hit.path),
                hit.kind
            ));
        }
    }
    let raw = dir
        .read_symlink(leaf)
        .map_err(|error| format!("cannot securely read symlink {path}: {error}"))?;
    let target = raw
        .to_str()
        .ok_or_else(|| format!("symlink {path} target is not portable UTF-8"))?;
    if let Some(hit) = crate::scan::scan_content(path, target).first() {
        return Err(format!(
            "package refused secret-shaped symlink target in {} ({})",
            terminal_safe(&hit.path),
            hit.kind
        ));
    }
    let resolved = lexical_symlink_target(path, target)?;
    let canonical_target = fs::canonicalize(workspace.root.join(&resolved))
        .map_err(|error| format!("symlink {path} has a missing target: {error}"))?;
    if !canonical_target.starts_with(&workspace.root) {
        return Err(format!("symlink {path} resolves outside the workspace"));
    }
    let target_kind = if canonical_target.is_dir() {
        "directory"
    } else if canonical_target.is_file() {
        "file"
    } else {
        return Err(format!(
            "symlink {path} does not resolve to a file or directory"
        ));
    };
    let prior = collected.entries.insert(
        path.to_string(),
        SnapshotEntry::Symlink {
            path: path.to_string(),
            target: target.to_string(),
            target_kind: target_kind.to_string(),
        },
    );
    if prior.is_some() {
        return Err(format!("package profile selects {path} more than once"));
    }
    Ok(())
}

struct WalkPolicy<'a> {
    workspace: &'a Workspace,
    allow_binary: bool,
    binary_paths: &'a BTreeSet<String>,
    excludes: &'a [String],
    allowed_names: &'a BTreeSet<String>,
}

fn walk(
    policy: &WalkPolicy<'_>,
    dir: &SafeDir,
    prefix: &str,
    collected: &mut Collected,
) -> Result<(), String> {
    let mut entries = dir
        .entries()
        .map_err(|error| format!("cannot list companion directory {prefix}: {error}"))?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    for entry in entries {
        let name = entry
            .name
            .to_str()
            .ok_or_else(|| format!("package directory {prefix} has a non-UTF-8 entry"))?;
        let path = format!("{prefix}/{name}");
        if excluded(&path, policy.excludes) {
            continue;
        }
        match entry.kind {
            EntryKind::File => collect_file(
                dir,
                &entry.name,
                &path,
                policy.allow_binary || policy.binary_paths.contains(&path),
                policy.allowed_names,
                collected,
            )?,
            EntryKind::Directory => {
                let child = dir.open_dir(&entry.name).map_err(|error| {
                    format!("cannot securely open companion directory {path}: {error}")
                })?;
                walk(policy, &child, &path, collected)?;
            }
            EntryKind::Symlink => collect_symlink(
                policy.workspace,
                dir,
                &entry.name,
                &path,
                policy.allowed_names,
                collected,
            )?,
            EntryKind::Other => {
                return Err(format!(
                    "package companion {path} is not a regular file, directory, or symlink"
                ))
            }
        }
    }
    Ok(())
}

fn collect_include(
    workspace: &Workspace,
    include: &IncludeSpec,
    excludes: &[String],
    binary_paths: &BTreeSet<String>,
    allowed_names: &BTreeSet<String>,
    collected: &mut Collected,
) -> Result<(), String> {
    let path = normalize_rel(&include.path, "included path")?;
    if path == workspace.store_rel || path.starts_with(&format!("{}/", workspace.store_rel)) {
        return Err(format!(
            "package profile must not include {path}: db/ already rides the semantic sync lane"
        ));
    }
    if path == ".git" || path.starts_with(".git/") {
        return Err(
            "package profile must declare Git as a dependency, not snapshot .git bytes".into(),
        );
    }
    if excluded(&path, excludes) {
        return Err(format!("top-level included path {path} is also excluded"));
    }
    let root = SafeDir::open(&workspace.root)
        .map_err(|error| format!("cannot securely open package workspace: {error}"))?;
    let parts: Vec<&str> = path.split('/').collect();
    let mut parent = root;
    for part in &parts[..parts.len() - 1] {
        parent = parent
            .open_dir(OsStr::new(part))
            .map_err(|error| format!("cannot traverse included path {path}: {error}"))?;
    }
    let leaf = OsStr::new(parts.last().expect("normalized path has a leaf"));
    let kind = parent
        .entries()
        .map_err(|error| format!("cannot list parent of {path}: {error}"))?
        .into_iter()
        .find(|entry| entry.name == leaf)
        .map(|entry| entry.kind)
        .ok_or_else(|| format!("included path does not exist: {path}"))?;
    match kind {
        EntryKind::File => collect_file(
            &parent,
            leaf,
            &path,
            include.allow_unscanned_binary || binary_paths.contains(&path),
            allowed_names,
            collected,
        ),
        EntryKind::Directory => {
            if include.allow_unscanned_binary {
                return Err(format!(
                    "package include {path} grants a directory-wide binary exception; use allow_unscanned_binary_paths for reviewed files"
                ));
            }
            let dir = parent.open_dir(leaf).map_err(|error| {
                format!("cannot securely open included directory {path}: {error}")
            })?;
            let before = collected.entries.len();
            let policy = WalkPolicy {
                workspace,
                allow_binary: include.allow_unscanned_binary,
                binary_paths,
                excludes,
                allowed_names,
            };
            walk(&policy, &dir, &path, collected)?;
            if collected.entries.len() == before {
                return Err(format!(
                    "included directory {path} contributes no package coordinates"
                ));
            }
            Ok(())
        }
        EntryKind::Symlink => {
            collect_symlink(workspace, &parent, leaf, &path, allowed_names, collected)
        }
        EntryKind::Other => Err(format!("included path {path} has an unsupported file type")),
    }
}

fn command_output(command: &mut Command, what: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("cannot {what}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cannot {what}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_string())
        .map_err(|_| format!("cannot {what}: output is not UTF-8"))
}

fn safe_git_remote(raw: String) -> Result<String, String> {
    if !crate::scan::scan_content("git-remote", &raw).is_empty() {
        return Err("Git remote contains credential-shaped content".into());
    }
    if raw.contains("://") {
        let parsed = url::Url::parse(&raw)
            .map_err(|_| "Git remote URL is malformed and was not recorded".to_string())?;
        if parsed.password().is_some()
            || (!parsed.username().is_empty() && parsed.username() != "git")
        {
            return Err("Git remote URL contains userinfo and was not recorded".into());
        }
    } else if let Some((user, _)) = raw.split_once('@') {
        if user != "git" || raw.matches('@').count() != 1 {
            return Err(
                "Git remote locator contains nonstandard userinfo and was not recorded".into(),
            );
        }
    }
    Ok(raw)
}

fn secure_entry_kind(root: &Path, rel: &str) -> Result<Option<EntryKind>, String> {
    if rel == "." {
        return Ok(Some(EntryKind::Directory));
    }
    let rel = normalize_rel(rel, "dependency path")?;
    let parts = rel.split('/').collect::<Vec<_>>();
    let mut dir = SafeDir::open(root)
        .map_err(|error| format!("cannot securely open dependency root: {error}"))?;
    for part in &parts[..parts.len() - 1] {
        match dir.open_dir(OsStr::new(part)) {
            Ok(child) => dir = child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "cannot securely traverse dependency path {rel}: {error}"
                ))
            }
        }
    }
    let leaf = OsStr::new(parts.last().expect("normalized dependency has a leaf"));
    let entries = dir
        .entries()
        .map_err(|error| format!("cannot inspect dependency path {rel}: {error}"))?;
    Ok(entries
        .into_iter()
        .find(|entry| entry.name == leaf)
        .map(|entry| entry.kind))
}

fn secure_directory(root: &Path, rel: &str) -> Result<Option<SafeDir>, String> {
    if rel == "." {
        return SafeDir::open(root)
            .map(Some)
            .map_err(|error| format!("cannot securely open dependency directory: {error}"));
    }
    let rel = normalize_rel(rel, "dependency directory")?;
    let mut dir = SafeDir::open(root)
        .map_err(|error| format!("cannot securely open dependency root: {error}"))?;
    for part in rel.split('/') {
        match dir.open_dir(OsStr::new(part)) {
            Ok(child) => dir = child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "cannot securely open dependency directory {rel}: {error}"
                ))
            }
        }
    }
    Ok(Some(dir))
}

fn collect_regular_store_paths(
    dir: &SafeDir,
    prefix: &str,
    paths: &mut Vec<String>,
) -> Result<(), String> {
    for entry in dir
        .entries()
        .map_err(|error| format!("cannot inspect private brain closure: {error}"))?
    {
        let name = entry
            .name
            .to_str()
            .ok_or_else(|| "private brain closure has a non-UTF-8 path".to_string())?;
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        match entry.kind {
            EntryKind::File => paths.push(path),
            EntryKind::Directory => {
                let child = dir.open_dir(&entry.name).map_err(|error| {
                    format!("cannot securely traverse private brain closure: {error}")
                })?;
                collect_regular_store_paths(&child, &path, paths)?;
            }
            EntryKind::Symlink | EntryKind::Other => {}
        }
    }
    Ok(())
}

fn projection_path_sha256(path: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"dbmd-projection-path-v1\0");
    digest.update(path.as_bytes());
    format!("{:x}", digest.finalize())
}

fn build_projection_manifest(
    workspace: &Workspace,
) -> Result<Option<(ProjectionManifest, String)>, String> {
    let Some(scope) = crate::local::load(&workspace.store)? else {
        return Ok(None);
    };
    if !scope.active() {
        return Ok(None);
    }
    if scope.keeps_home(SNAPSHOT_RECORD) || scope.keeps_home(&format!("{OBJECT_PREFIX}/probe.blob"))
    {
        return Err(
            ".sevralocal cannot cover Sevra package snapshot records or immutable objects".into(),
        );
    }
    let root = SafeDir::open(&workspace.store)
        .map_err(|error| format!("cannot securely open private brain store: {error}"))?;
    let mut present = Vec::new();
    collect_regular_store_paths(&root, "", &mut present)?;
    let path_hashes = present
        .into_iter()
        .filter(|path| path != crate::local::FILE_NAME && scope.keeps_home(path))
        .map(|path| projection_path_sha256(&path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if path_hashes.is_empty() {
        return Err("active .sevralocal policy has no private regular-file closure".into());
    }
    if path_hashes.len() > MAX_FILES {
        return Err(format!(
            "private brain projection exceeds the {MAX_FILES}-path package bound"
        ));
    }
    let policy_sha256 = format!("{:x}", Sha256::digest(scope.raw().as_bytes()));
    Ok(Some((
        ProjectionManifest {
            version: 1,
            algorithm: "sha256".into(),
            path_hashes,
        },
        policy_sha256,
    )))
}

fn validate_projection_manifest(manifest: &ProjectionManifest) -> Result<(), String> {
    if manifest.version != 1
        || manifest.algorithm != "sha256"
        || manifest.path_hashes.len() > MAX_FILES
    {
        return Err("package projection manifest has an unsupported format".into());
    }
    let mut prior: Option<&str> = None;
    for hash in &manifest.path_hashes {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || prior.is_some_and(|value| value >= hash.as_str())
        {
            return Err(
                "package projection manifest commitments are not canonical lowercase SHA-256"
                    .into(),
            );
        }
        prior = Some(hash);
    }
    if ["DB.md", "assets.jsonl"].into_iter().any(|path| {
        manifest
            .path_hashes
            .binary_search(&projection_path_sha256(path))
            .is_ok()
    }) {
        return Err("package projection manifest covers required hosted brain metadata".into());
    }
    Ok(())
}

fn verify_sevralocal_closure(
    workspace: &Workspace,
    dependency_path: &str,
    policy_sha256: &str,
    minimum_entries: usize,
) -> Result<(), String> {
    let expected_path = format!("{}/{}", workspace.store_rel, crate::local::FILE_NAME);
    if dependency_path != expected_path {
        return Err(format!(
            "sevralocal closure verification requires dependency path {expected_path}"
        ));
    }
    let scope = crate::local::load(&workspace.store)?
        .ok_or_else(|| "private brain policy is absent".to_string())?;
    let actual_sha256 = format!("{:x}", Sha256::digest(scope.raw().as_bytes()));
    if actual_sha256 != policy_sha256.to_ascii_lowercase() {
        return Err("private brain policy does not match the checkpointed policy digest".into());
    }
    let entries = scope
        .raw()
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let entry = line.strip_suffix('\r').unwrap_or(line);
            (!entry.trim().is_empty() && !entry.starts_with('#')).then_some((index + 1, entry))
        })
        .collect::<Vec<_>>();
    if entries.len() < minimum_entries {
        return Err(format!(
            "private brain policy has {} effective entries; at least {minimum_entries} are required",
            entries.len()
        ));
    }
    let root = SafeDir::open(&workspace.store)
        .map_err(|error| format!("cannot securely open private brain store: {error}"))?;
    let mut present = Vec::new();
    collect_regular_store_paths(&root, "", &mut present)?;
    present.retain(|path| path != crate::local::FILE_NAME);
    for (line, entry) in entries {
        let matcher = GlobBuilder::new(entry)
            .backslash_escape(true)
            .build()
            .map_err(|_| format!("private brain policy line {line} is not a valid glob"))?
            .compile_matcher();
        if !present.iter().any(|path| matcher.is_match(path)) {
            return Err(format!(
                "private brain policy line {line} has no restored regular file"
            ));
        }
    }
    Ok(())
}

fn required_child_path(base: &str, child: &str) -> String {
    if base == "." {
        child.to_string()
    } else {
        format!("{base}/{child}")
    }
}

fn verify_dependency_path(
    workspace: &Workspace,
    rel: &str,
    verification: Option<&PathVerification>,
) -> Result<(), String> {
    let kind =
        secure_entry_kind(&workspace.root, rel)?.ok_or_else(|| "path is absent".to_string())?;
    match verification {
        Some(PathVerification::RegularFile { allow_empty }) => {
            if kind != EntryKind::File {
                return Err("path is not a no-follow regular file".into());
            }
            if !allow_empty {
                let file = safe_path::open_regular(&workspace.root, rel)
                    .map_err(|error| format!("cannot securely inspect file: {error}"))?
                    .ok_or_else(|| "path is absent".to_string())?;
                if file
                    .metadata()
                    .map_err(|error| format!("cannot inspect file metadata: {error}"))?
                    .len()
                    == 0
                {
                    return Err("regular file is empty".into());
                }
            }
        }
        Some(PathVerification::Directory {
            allow_empty,
            required,
        }) => {
            if kind != EntryKind::Directory {
                return Err("path is not a no-follow directory".into());
            }
            let directory = secure_directory(&workspace.root, rel)?
                .ok_or_else(|| "path is absent".to_string())?;
            if !allow_empty
                && directory
                    .entries()
                    .map_err(|error| format!("cannot inspect directory: {error}"))?
                    .is_empty()
            {
                return Err("directory is empty".into());
            }
            for child in required {
                let child = required_child_path(rel, child);
                match secure_entry_kind(&workspace.root, &child)? {
                    Some(EntryKind::File | EntryKind::Directory) => {}
                    Some(_) => return Err(format!("required child {child} is not a regular path")),
                    None => return Err(format!("required child {child} is absent")),
                }
            }
        }
        Some(PathVerification::SevralocalClosure {
            policy_sha256,
            minimum_entries,
        }) => {
            if kind != EntryKind::File {
                return Err("private brain policy is not a no-follow regular file".into());
            }
            verify_sevralocal_closure(workspace, rel, policy_sha256, *minimum_entries)?;
        }
        None => {
            match kind {
                EntryKind::File => {
                    let file = safe_path::open_regular(&workspace.root, rel)
                        .map_err(|error| format!("cannot securely inspect file: {error}"))?
                        .ok_or_else(|| "path is absent".to_string())?;
                    if file
                        .metadata()
                        .map_err(|error| format!("cannot inspect file metadata: {error}"))?
                        .len()
                        == 0
                    {
                        return Err("regular file is empty; declare an explicit verification if intentional".into());
                    }
                }
                EntryKind::Directory => {
                    let directory = secure_directory(&workspace.root, rel)?
                        .ok_or_else(|| "path is absent".to_string())?;
                    if directory
                        .entries()
                        .map_err(|error| format!("cannot inspect directory: {error}"))?
                        .is_empty()
                    {
                        return Err(
                            "directory is empty; declare an explicit verification if intentional"
                                .into(),
                        );
                    }
                }
                EntryKind::Symlink | EntryKind::Other => {
                    return Err("path is not a no-follow regular file or directory".into())
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn secret_file_is_owner_only(workspace: &Workspace, rel: &str) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let file = safe_path::open_regular(&workspace.root, rel)
        .map_err(|error| format!("cannot inspect local secret custody: {error}"))?
        .ok_or_else(|| "local secret custody is absent".to_string())?;
    let mode = file
        .metadata()
        .map_err(|error| format!("cannot inspect local secret custody mode: {error}"))?
        .mode()
        & 0o777;
    Ok(mode & 0o077 == 0)
}

#[cfg(not(unix))]
fn secret_file_is_owner_only(_workspace: &Workspace, _rel: &str) -> Result<bool, String> {
    Ok(true)
}

fn dependency_receipts(
    workspace: &Workspace,
    specs: &[DependencySpec],
    vault_names: Option<&BTreeSet<String>>,
) -> Vec<DependencyReceipt> {
    specs
        .iter()
        .map(|spec| {
            let mut receipt = DependencyReceipt {
                id: spec.id.clone(),
                kind: spec.kind.clone(),
                required: spec.required,
                impact: spec.impact.clone(),
                status: "unresolved".into(),
                path: spec.path.clone(),
                name: spec.name.clone(),
                locator: spec.locator.clone(),
                remote: spec.remote.clone(),
                local_path: spec.local_path.clone(),
                verification: spec.verification.clone(),
                remote_url: None,
                detail: None,
            };
            match spec.kind.as_str() {
                "git" => {
                    let path = workspace.root.join(spec.path.as_deref().unwrap_or(""));
                    let remote = spec.remote.as_deref().unwrap_or("origin");
                    receipt.remote_url = match command_output(
                        Command::new("git")
                            .args(["-C"])
                            .arg(&path)
                            .args(["remote", "get-url", remote]),
                        "inspect Git dependency remote",
                    ) {
                        Ok(remote_url) => match safe_git_remote(remote_url) {
                            Ok(remote_url) => Some(remote_url),
                            Err(error) => {
                                receipt.detail = Some(error);
                                None
                            }
                        },
                        Err(error) => {
                            receipt.detail = Some(error);
                            None
                        }
                    };
                    let head = command_output(
                        Command::new("git")
                            .args(["-C"])
                            .arg(&path)
                            .args(["rev-parse", "--verify", "HEAD^{commit}"]),
                        "verify Git dependency history",
                    );
                    let shallow = command_output(
                        Command::new("git")
                            .args(["-C"])
                            .arg(&path)
                            .args(["rev-parse", "--is-shallow-repository"]),
                        "verify Git dependency history depth",
                    );
                    if receipt.remote_url.is_some()
                        && head.is_ok()
                        && matches!(shallow.as_deref(), Ok("false"))
                    {
                        receipt.status = "resolved".into();
                    } else if receipt.detail.is_none() {
                        receipt.detail = Some(match (head, shallow) {
                            (Err(error), _) | (_, Err(error)) => error,
                            (_, Ok(value)) if value == "true" => {
                                "Git dependency is a shallow checkout".into()
                            }
                            _ => "Git dependency history could not be verified".into(),
                        });
                    }
                }
                "path" => {
                    match verify_dependency_path(
                        workspace,
                        spec.path.as_deref().unwrap_or(""),
                        spec.verification.as_ref(),
                    ) {
                        Ok(()) => {
                        receipt.status = "resolved".into();
                        }
                        Err(error) => receipt.detail = Some(error),
                    }
                }
                "secret" => {
                    let vault_resolved = vault_names
                        .is_some_and(|names| names.contains(spec.name.as_deref().unwrap_or("")));
                    let local_result = spec.local_path.as_deref().map(|path| {
                        verify_dependency_path(workspace, path, spec.verification.as_ref())?;
                        if matches!(
                            spec.verification,
                            None | Some(PathVerification::RegularFile { .. })
                        ) && !secret_file_is_owner_only(workspace, path)?
                        {
                            return Err("local secret custody is not owner-only".into());
                        }
                        Ok(())
                    });
                    if vault_resolved || matches!(local_result, Some(Ok(()))) {
                        receipt.status = "resolved".into();
                    } else if let Some(Err(error)) = local_result {
                        receipt.detail = Some(error);
                    } else if vault_names.is_some() {
                        receipt.detail = Some("vault item name is absent".into());
                    } else {
                        receipt.detail = Some("vault custody was not checked".into());
                    }
                }
                "live" | "external" => {
                    receipt.detail = Some(
                        "declared for operator restoration; Sevra never starts or probes arbitrary external systems"
                            .into(),
                    )
                }
                _ => unreachable!("profile validation rejects dependency kind"),
            }
            receipt
        })
        .collect()
}

fn vault_names(cfg: &Config, brain: &str) -> BTreeSet<String> {
    let response = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/vault", commands::enc(brain)),
            None,
            true,
        ),
        "read package vault names",
    );
    response
        .get("items")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("hub returned malformed package vault metadata", None))
        .iter()
        .map(|item| {
            item.get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty() && name.len() <= 64)
                .unwrap_or_else(|| fail("hub returned an invalid package vault name", None))
                .to_string()
        })
        .collect()
}

fn dbmd(store: &Path, args: &[&str], what: &str) -> Result<Value, String> {
    dbmd_with_input(store, args, what, None)
}

fn dbmd_with_input(
    store: &Path,
    args: &[&str],
    what: &str,
    input: Option<&[u8]>,
) -> Result<Value, String> {
    let mut command = Command::new("dbmd");
    command.arg("--json").args(args).current_dir(store);
    let output = if let Some(input) = input {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("cannot run dbmd for {what}: {error}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| format!("cannot open dbmd stdin for {what}"))?
            .write_all(input)
            .map_err(|error| format!("cannot supply dbmd projection for {what}: {error}"))?;
        child
            .wait_with_output()
            .map_err(|error| format!("cannot wait for dbmd {what}: {error}"))?
    } else {
        command
            .output()
            .map_err(|error| format!("cannot run dbmd for {what}: {error}"))?
    };
    if !output.status.success() {
        return Err(format!(
            "dbmd {what} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("dbmd {what} returned invalid JSON: {error}"))
}

fn ignored_object_cache(workspace: &Workspace) -> Result<(), String> {
    let candidate = format!("{}/{OBJECT_PREFIX}/probe.blob", workspace.store_rel);
    let inside = Command::new("git")
        .args(["-C"])
        .arg(&workspace.root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output();
    if !inside.is_ok_and(|output| output.status.success()) {
        return Ok(());
    }
    let ignored = Command::new("git")
        .args(["-C"])
        .arg(&workspace.root)
        .args(["check-ignore", "--no-index", "--quiet", &candidate])
        .status()
        .map_err(|error| format!("cannot verify package object ignore policy: {error}"))?;
    if !ignored.success() {
        return Err(format!(
            "generated package objects must stay out of Git; add `{}/{OBJECT_PREFIX}/` to the workspace .gitignore",
            workspace.store_rel,
        ));
    }
    Ok(())
}

fn existing_snapshot_root(workspace: &Workspace) -> Result<Option<String>, String> {
    let Some(bytes) = safe_path::read_regular(&workspace.store, SNAPSHOT_RECORD)
        .map_err(|error| format!("cannot read prior package snapshot: {error}"))?
    else {
        return Ok(None);
    };
    // Checkpoint owns this generated record and may need to replace a snapshot
    // emitted by an older CLI. Read only its root for no-op detection here;
    // restore and verify still deserialize the complete current schema with
    // deny_unknown_fields before trusting any signed recovery material.
    let value: Value = extract_fenced_json(&bytes, SNAPSHOT_FENCE)?;
    let root = value
        .get("snapshot_root")
        .and_then(Value::as_str)
        .ok_or_else(|| "prior package snapshot has no snapshot_root".to_string())?;
    if root.len() != 64 || !root.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("prior package snapshot has an invalid snapshot_root".into());
    }
    Ok(Some(root.to_ascii_lowercase()))
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("JSON string is valid YAML string syntax")
}

fn snapshot_markdown(envelope: &SnapshotEnvelope, created: &str) -> Result<Vec<u8>, String> {
    let mut assets = BTreeSet::new();
    for entry in &envelope.core.entries {
        if let SnapshotEntry::File { asset, .. } = entry {
            assets.insert(asset);
        }
    }
    let encoded = serde_json::to_string_pretty(envelope)
        .map_err(|error| format!("cannot encode package snapshot record: {error}"))?;
    let mut markdown = format!(
        "---\ntype: operational\nmeta-type: operational\ntitle: {}\nsummary: {}\nprofile: {}\nsnapshot_root: {}\ncreated: {}\nupdated: {}\nassets:\n",
        yaml_string("Sevra package snapshot"),
        yaml_string("Generated recovery closure for the brain's working companion files."),
        yaml_string(&envelope.core.profile),
        yaml_string(&envelope.snapshot_root),
        yaml_string(created),
        yaml_string(&envelope.created_at),
    );
    for asset in assets {
        markdown.push_str(&format!("  - {}\n", yaml_string(asset)));
    }
    markdown.push_str(&format!(
        "---\n\n# Sevra package snapshot\n\nGenerated by `sevra package checkpoint`. Runtime files remain authoritative at their workspace paths; these immutable objects are recovery snapshots, not editable duplicates.\n\n```{SNAPSHOT_FENCE}\n{encoded}\n```\n"
    ));
    Ok(markdown.into_bytes())
}

fn created_from_prior(workspace: &Workspace, fallback: &str) -> String {
    let Ok(Some(bytes)) = safe_path::read_regular(&workspace.store, SNAPSHOT_RECORD) else {
        return fallback.to_string();
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return fallback.to_string();
    };
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("created: ") {
            return value.trim().trim_matches('"').to_string();
        }
        if line == "---" && text.find(line).is_some_and(|index| index > 0) {
            break;
        }
    }
    fallback.to_string()
}

fn stage_snapshot(
    workspace: &Workspace,
    profile_name: &str,
    profile: &ProfileSpec,
    names: &BTreeSet<String>,
) -> Result<PackageReport, String> {
    ignored_object_cache(workspace)?;
    let excludes: Vec<String> = profile
        .exclude
        .iter()
        .map(|path| normalize_rel(path, "excluded path"))
        .collect::<Result<_, _>>()?;
    let allowed_names: BTreeSet<String> = profile
        .allow_secret_named_paths
        .iter()
        .map(|path| normalize_rel(path, "secret-named exception"))
        .collect::<Result<_, _>>()?;
    let binary_paths: BTreeSet<String> = profile
        .allow_unscanned_binary_paths
        .iter()
        .map(|path| normalize_rel(path, "binary exception"))
        .collect::<Result<_, _>>()?;
    let mut collected = Collected::default();
    for include in &profile.include {
        collect_include(
            workspace,
            include,
            &excludes,
            &binary_paths,
            &allowed_names,
            &mut collected,
        )?;
    }
    let entries = collected.entries.into_values().collect::<Vec<_>>();
    validate_symlink_closure(&entries)?;
    let projection_build = build_projection_manifest(workspace)?;
    let expected_policy_path = format!("{}/{}", workspace.store_rel, crate::local::FILE_NAME);
    let private_dependency = projection_build
        .as_ref()
        .and_then(|(_, actual_policy_sha256)| {
            profile.dependencies.iter().find(|dependency| {
                dependency.kind == "path"
                    && dependency.impact == "semantic"
                    && dependency.path.as_deref() == Some(expected_policy_path.as_str())
                    && matches!(
                        dependency.verification.as_ref(),
                        Some(PathVerification::SevralocalClosure { policy_sha256, .. })
                            if policy_sha256.eq_ignore_ascii_case(actual_policy_sha256)
                    )
            })
        });
    if projection_build.is_some() && private_dependency.is_none() {
        return Err(
            "an active .sevralocal requires a matching semantic sevralocal_closure dependency in the package profile"
                .into(),
        );
    }
    let dependencies = dependency_receipts(workspace, &profile.dependencies, Some(names));
    if let Some(private_dependency) = private_dependency {
        if !dependencies
            .iter()
            .any(|receipt| receipt.id == private_dependency.id && receipt.status == "resolved")
        {
            return Err(
                "private brain policy changed while the package projection was being checkpointed"
                    .into(),
            );
        }
    }
    let projection = projection_build.map(|(manifest, _)| manifest);
    let required_unresolved: Vec<&str> = dependencies
        .iter()
        .filter(|dependency| dependency.required && dependency.status != "resolved")
        .map(|dependency| dependency.id.as_str())
        .collect();
    if !required_unresolved.is_empty() {
        return Err(format!(
            "required package dependencies are unresolved: {}",
            required_unresolved.join(", ")
        ));
    }
    let core = SnapshotCore {
        version: 1,
        profile: profile_name.to_string(),
        profile_sha256: canonical_hash(profile)?,
        store: workspace.store_rel.clone(),
        entries,
        dependencies,
        projection,
    };
    let snapshot_root = canonical_hash(&core)?;
    let prior_root = existing_snapshot_root(workspace)?;
    let changed = prior_root.as_deref() != Some(snapshot_root.as_str());
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| format!("cannot format package timestamp: {error}"))?;
    let created = created_from_prior(workspace, &now);
    let envelope = SnapshotEnvelope {
        version: 1,
        snapshot_root: snapshot_root.clone(),
        created_at: now,
        core,
    };
    let store_dir = SafeDir::open(&workspace.store)
        .map_err(|error| format!("cannot securely open brain store: {error}"))?;
    for (hash, bytes) in &collected.objects {
        let asset = format!("{OBJECT_PREFIX}/{hash}.blob");
        match store_dir
            .open_relative(&asset)
            .map_err(|error| format!("cannot inspect package object {hash}: {error}"))?
        {
            Some(mut file) => {
                let mut present = Vec::new();
                file.read_to_end(&mut present)
                    .map_err(|error| format!("cannot verify package object {hash}: {error}"))?;
                if present.len() != bytes.len()
                    || format!("{:x}", Sha256::digest(&present)) != *hash
                {
                    return Err(format!(
                        "immutable package object {hash} exists with different bytes; remove the corrupt cache object and retry"
                    ));
                }
            }
            None => store_dir
                .atomic_create(&asset, bytes, true, 0o600)
                .map_err(|error| format!("cannot create package object {hash}: {error}"))?,
        }
    }
    if changed {
        let markdown = snapshot_markdown(&envelope, &created)?;
        store_dir
            .atomic_write(SNAPSHOT_RECORD, &markdown, true, 0o600)
            .map_err(|error| format!("cannot write package snapshot record: {error}"))?;
    }
    dbmd(
        &workspace.store,
        &["assets", "refresh-wrapper", SNAPSHOT_RECORD],
        "package asset reconciliation",
    )?;
    let live: BTreeSet<String> = collected.objects.keys().cloned().collect();
    let objects_dir = workspace.store.join(OBJECT_PREFIX);
    if let Ok(entries) = fs::read_dir(&objects_dir) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Some(hash) = name.strip_suffix(".blob") else {
                continue;
            };
            if hash.len() == 64
                && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !live.contains(hash)
            {
                store_dir
                    .remove_regular(&format!("{OBJECT_PREFIX}/{name}"))
                    .map_err(|error| {
                        format!("cannot prune stale package object {name}: {error}")
                    })?;
            }
        }
    }
    // Indexes are derived state and another curation flow may have changed
    // authored records since the last checkpoint. Rebuild them on every run
    // so the package command is an agent-friendly, self-contained preflight.
    dbmd(
        &workspace.store,
        &["index", "rebuild"],
        "package index rebuild",
    )?;
    if changed {
        dbmd(
            &workspace.store,
            &[
                "log",
                "update",
                "records/operational/sevra-package-snapshot",
                "-m",
                "Checkpointed the content-addressed working recovery closure.",
            ],
            "package curator log",
        )?;
    }
    dbmd(
        &workspace.store,
        &["validate", "--all"],
        "package validation",
    )?;
    let files = envelope
        .core
        .entries
        .iter()
        .filter(|entry| matches!(entry, SnapshotEntry::File { .. }))
        .count();
    let symlinks = envelope.core.entries.len() - files;
    let dependencies_resolved = envelope
        .core
        .dependencies
        .iter()
        .filter(|dependency| dependency.status == "resolved")
        .count();
    let dependencies_unresolved = envelope.core.dependencies.len() - dependencies_resolved;
    let semantic_unresolved_dependencies = envelope
        .core
        .dependencies
        .iter()
        .filter(|dependency| dependency.status != "resolved" && dependency.impact == "semantic")
        .map(|dependency| dependency.id.clone())
        .collect::<Vec<_>>();
    Ok(PackageReport {
        profile: profile_name.to_string(),
        snapshot_root,
        files,
        symlinks,
        objects: collected.objects.len(),
        bytes: collected.bytes,
        changed,
        unscanned_files: collected.unscanned,
        dependencies_resolved,
        dependencies_unresolved,
        brain_complete: semantic_unresolved_dependencies.is_empty(),
        semantic_unresolved_dependencies,
        operational_ready: dependencies_unresolved == 0,
    })
}

pub fn checkpoint_command(
    cfg: &Config,
    workspace_path: String,
    brain: String,
    profile_name: String,
    allow_secrets: bool,
    confirm_bulk: Option<String>,
) {
    let workspace = discover_workspace(&workspace_path).unwrap_or_else(|error| fail(&error, None));
    let held_store = SafeDir::open(&workspace.store).unwrap_or_else(|error| {
        fail(
            &format!("cannot open package store for locking: {error}"),
            None,
        )
    });
    let _package_lock = held_store
        .lock_relative(PACKAGE_LOCK)
        .unwrap_or_else(|error| {
            fail(
                &format!("cannot lock package lifecycle state: {error}"),
                None,
            )
        });
    if !workspace.store.join(".sevra-v2.json").is_file() {
        fail(
            "package checkpoint requires an established Link.md v2 checkout; run one ordinary `sevra push --brain <brain> db` first",
            Some(json!({ "code": "package_v2_checkout_required" })),
        );
    }
    let profile = read_profile(&workspace, &profile_name)
        .unwrap_or_else(|error| fail(&error, Some(json!({ "code": "package_profile_invalid" }))));
    let (progress_done, progress) = progress_heartbeat(
        "sevra: checkpointing the signed working closure; unchanged content reuses existing hashes",
        "sevra: still validating and syncing the working closure",
    );
    let names = vault_names(cfg, &brain);
    write_vault_names(&workspace, &brain, &names).unwrap_or_else(|error| {
        fail(
            &format!("package vault-name receipt could not be refreshed: {error}"),
            Some(json!({ "code": "package_vault_receipt_failed" })),
        )
    });
    let report = stage_snapshot(&workspace, &profile_name, &profile, &names)
        .unwrap_or_else(|error| fail(&error, Some(json!({ "code": "package_checkpoint_failed" }))));
    commands::push(
        cfg,
        workspace.store.to_string_lossy().as_ref(),
        &brain,
        PushOptions {
            force: false,
            allow_secrets,
            skip_assets: false,
            resume_local_policy: false,
            confirm_bulk: confirm_bulk.as_deref(),
            withdraw_from_hosting: &[],
            withdraw_reason: None,
            package_report: Some(&report),
        },
    );
    stop_progress(progress_done, progress);
}

fn dependency_spec_from_receipt(receipt: &DependencyReceipt) -> DependencySpec {
    DependencySpec {
        id: receipt.id.clone(),
        kind: receipt.kind.clone(),
        required: receipt.required,
        impact: receipt.impact.clone(),
        path: receipt.path.clone(),
        name: receipt.name.clone(),
        locator: receipt.locator.clone(),
        remote: receipt.remote.clone(),
        local_path: receipt.local_path.clone(),
        verification: receipt.verification.clone(),
    }
}

fn binary_allowed_for_path(profile: &ProfileSpec, path: &str) -> bool {
    profile
        .allow_unscanned_binary_paths
        .iter()
        .any(|allowed| allowed == path)
        || profile
            .include
            .iter()
            .any(|include| include.path == path && include.allow_unscanned_binary)
}

fn validate_snapshot_against_profile(
    workspace: &Workspace,
    profile: &ProfileSpec,
    envelope: &SnapshotEnvelope,
) -> Result<(), String> {
    let paths = envelope
        .core
        .entries
        .iter()
        .map(|entry| entry.path())
        .collect::<BTreeSet<_>>();
    for include in &profile.include {
        if !paths
            .iter()
            .any(|path| **path == include.path || path.starts_with(&format!("{}/", include.path)))
        {
            return Err(format!(
                "package snapshot omits selected include `{}`",
                include.path
            ));
        }
    }
    for allowed in &profile.allow_unscanned_binary_paths {
        if !paths.contains(allowed.as_str()) {
            return Err(format!(
                "package snapshot omits reviewed binary exception `{allowed}`"
            ));
        }
    }
    for entry in &envelope.core.entries {
        let path = entry.path();
        if path == ".git" || path.starts_with(".git/") {
            return Err(format!(
                "package snapshot path {path} overlaps reserved Git state"
            ));
        }
        if path == workspace.store_rel || path.starts_with(&format!("{}/", workspace.store_rel)) {
            return Err(format!(
                "package snapshot path {path} overlaps the brain store"
            ));
        }
        if generated_cache_path(path) {
            return Err(format!(
                "package snapshot contains generated cache path {path}"
            ));
        }
        if !path_selected(profile, path) || excluded(path, &profile.exclude) {
            return Err(format!(
                "package snapshot path {path} is outside the current profile closure"
            ));
        }
        if matches!(
            entry,
            SnapshotEntry::File {
                unscanned_binary: true,
                ..
            }
        ) && !binary_allowed_for_path(profile, path)
        {
            return Err(format!(
                "package snapshot grants an undeclared binary exception to {path}"
            ));
        }
    }
    let snapshot_dependencies = envelope
        .core
        .dependencies
        .iter()
        .map(dependency_spec_from_receipt)
        .collect::<Vec<_>>();
    if snapshot_dependencies != profile.dependencies {
        return Err(
            "package snapshot dependency closure does not match the current profile".into(),
        );
    }
    for receipt in &envelope.core.dependencies {
        if !matches!(receipt.status.as_str(), "resolved" | "unresolved") {
            return Err(format!(
                "package dependency `{}` has an invalid status",
                receipt.id
            ));
        }
        if let Some(remote_url) = &receipt.remote_url {
            safe_git_remote(remote_url.clone())
                .map_err(|error| format!("package dependency `{}`: {error}", receipt.id))?;
        }
    }
    Ok(())
}

fn validate_snapshot_objects(
    workspace: &Workspace,
    profile: &ProfileSpec,
    entries: &[SnapshotEntry],
) -> Result<(), String> {
    let allowed_names = profile
        .allow_secret_named_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for entry in entries {
        let SnapshotEntry::File {
            path,
            sha256,
            bytes,
            asset,
            unscanned_binary,
            ..
        } = entry
        else {
            continue;
        };
        let Some(object) = safe_path::read_regular(&workspace.store, asset)
            .map_err(|error| format!("cannot inspect package object for {path}: {error}"))?
        else {
            continue;
        };
        if object.len() as u64 != *bytes || format!("{:x}", Sha256::digest(&object)) != *sha256 {
            continue;
        }
        let rescanned = scan_companion(
            path,
            &object,
            allowed_names.contains(path.as_str()),
            binary_allowed_for_path(profile, path),
        )?;
        if rescanned != *unscanned_binary {
            return Err(format!(
                "package snapshot binary classification changed for {path}"
            ));
        }
    }
    Ok(())
}

fn load_snapshot(workspace: &Workspace, profile: &str) -> Result<SnapshotEnvelope, String> {
    valid_name(profile, "profile name")?;
    let bytes = safe_path::read_regular(&workspace.store, SNAPSHOT_RECORD)
        .map_err(|error| format!("cannot read package snapshot: {error}"))?
        .ok_or_else(|| format!("brain has no {SNAPSHOT_RECORD}"))?;
    let envelope: SnapshotEnvelope = extract_fenced_json(&bytes, SNAPSHOT_FENCE)?;
    if envelope.version != 1
        || envelope.core.version != 1
        || envelope.core.profile_sha256.len() != 64
        || !envelope
            .core
            .profile_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("unsupported package snapshot version".into());
    }
    if envelope.core.profile != profile {
        return Err(format!(
            "package snapshot is for profile `{}`, not `{profile}`",
            envelope.core.profile
        ));
    }
    let current_profile = read_profile(workspace, profile)?;
    if canonical_hash(&current_profile)? != envelope.core.profile_sha256 {
        return Err(format!(
            "package profile `{profile}` changed after this snapshot; run `sevra package checkpoint`"
        ));
    }
    if envelope.core.store != workspace.store_rel {
        return Err(format!(
            "package snapshot expects store `{}`, not `{}`",
            envelope.core.store, workspace.store_rel
        ));
    }
    let root = canonical_hash(&envelope.core)?;
    if root != envelope.snapshot_root {
        return Err("package snapshot root does not match its canonical contents".into());
    }
    if let Some(projection) = envelope.core.projection.as_ref() {
        validate_projection_manifest(projection)?;
    }
    let mut paths = BTreeSet::new();
    for entry in &envelope.core.entries {
        let path = normalize_rel(entry.path(), "snapshot path")?;
        if !paths.insert(path.clone()) {
            return Err("package snapshot contains a duplicate path".into());
        }
        if let SnapshotEntry::File {
            sha256,
            bytes,
            asset,
            mode,
            ..
        } = entry
        {
            if sha256.len() != 64
                || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || asset != &format!("{OBJECT_PREFIX}/{sha256}.blob")
                || *bytes > MAX_FILE_BYTES
                || !matches!(*mode, 0o644 | 0o755)
            {
                return Err(format!(
                    "package snapshot has invalid file metadata for {path}"
                ));
            }
        }
    }
    // The signer authenticates bytes, not package semantics. Re-derive the
    // selected path/dependency closure and rescan every available object before
    // any restore or pull can install it.
    validate_snapshot_against_profile(workspace, &current_profile, &envelope)?;
    validate_symlink_closure(&envelope.core.entries)?;
    validate_snapshot_objects(workspace, &current_profile, &envelope.core.entries)?;
    Ok(envelope)
}

fn checkout_from_snapshot(brain: &str, envelope: &SnapshotEnvelope) -> PackageCheckout {
    PackageCheckout {
        version: 1,
        brain: brain.to_string(),
        profile: envelope.core.profile.clone(),
        snapshot_root: envelope.snapshot_root.clone(),
        entries: envelope.core.entries.clone(),
    }
}

fn validate_checkout(checkout: &PackageCheckout, workspace: &Workspace) -> Result<(), String> {
    if checkout.version != 1
        || !is_canonical_brain_id(&checkout.brain)
        || checkout.snapshot_root.len() != 64
        || !checkout
            .snapshot_root
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("package checkout receipt has an invalid identity".into());
    }
    valid_name(&checkout.profile, "package checkout profile")?;
    let mut paths = BTreeSet::new();
    for entry in &checkout.entries {
        let path = normalize_rel(entry.path(), "package checkout path")?;
        if path == workspace.store_rel || path.starts_with(&format!("{}/", workspace.store_rel)) {
            return Err("package checkout receipt overlaps the brain store".into());
        }
        if !paths.insert(path) {
            return Err("package checkout receipt contains a duplicate path".into());
        }
        if let SnapshotEntry::File {
            sha256,
            bytes,
            mode,
            asset,
            ..
        } = entry
        {
            if sha256.len() != 64
                || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || asset != &format!("{OBJECT_PREFIX}/{sha256}.blob")
                || *bytes > MAX_FILE_BYTES
                || !matches!(*mode, 0o644 | 0o755)
            {
                return Err("package checkout receipt has invalid file metadata".into());
            }
        }
    }
    validate_symlink_closure(&checkout.entries)
}

fn read_package_checkout(workspace: &Workspace) -> Result<PackageCheckout, String> {
    let bytes = safe_path::read_regular(&workspace.store, CHECKOUT_RECEIPT)
        .map_err(|error| format!("cannot read package checkout receipt: {error}"))?
        .ok_or_else(|| {
            "workspace has no package checkout receipt; use a fresh `sevra package restore` or verify an exact package before adopting this lifecycle"
                .to_string()
        })?;
    let checkout: PackageCheckout = serde_json::from_slice(&bytes)
        .map_err(|error| format!("package checkout receipt is invalid: {error}"))?;
    validate_checkout(&checkout, workspace)?;
    Ok(checkout)
}

fn write_package_checkout(workspace: &Workspace, checkout: &PackageCheckout) -> Result<(), String> {
    validate_checkout(checkout, workspace)?;
    let mut bytes = serde_json::to_vec_pretty(checkout)
        .map_err(|error| format!("cannot encode package checkout receipt: {error}"))?;
    bytes.push(b'\n');
    safe_path::atomic_write(&workspace.store, CHECKOUT_RECEIPT, &bytes, false, 0o600)
        .map_err(|error| format!("cannot write package checkout receipt: {error}"))
}

fn entry_matches(workspace: &Workspace, entry: &SnapshotEntry) -> Result<bool, String> {
    match entry {
        SnapshotEntry::File {
            path,
            sha256,
            bytes,
            mode,
            ..
        } => {
            let Some(mut file) = safe_path::open_regular(&workspace.root, path)
                .map_err(|error| format!("cannot inspect package path {path}: {error}"))?
            else {
                return Ok(false);
            };
            let metadata = file
                .metadata()
                .map_err(|error| format!("cannot inspect package path {path}: {error}"))?;
            if metadata.len() != *bytes || portable_mode(&metadata) != *mode {
                return Ok(false);
            }
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|error| format!("cannot read package path {path}: {error}"))?;
            Ok(format!("{:x}", Sha256::digest(data)) == *sha256)
        }
        SnapshotEntry::Symlink { path, target, .. } => {
            match fs::symlink_metadata(workspace.root.join(path)) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    fs::read_link(workspace.root.join(path))
                        .map(|actual| actual == Path::new(target))
                        .map_err(|error| format!("cannot read package symlink {path}: {error}"))
                }
                Ok(_) => Ok(false),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(format!("cannot inspect package symlink {path}: {error}")),
            }
        }
    }
}

fn path_absent(workspace: &Workspace, path: &str) -> Result<bool, String> {
    match fs::symlink_metadata(workspace.root.join(path)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("cannot inspect package path {path}: {error}")),
        Ok(_) => Ok(false),
    }
}

fn coordinate_matches(
    workspace: &Workspace,
    path: &str,
    entry: Option<&SnapshotEntry>,
) -> Result<bool, String> {
    match entry {
        Some(entry) => entry_matches(workspace, entry),
        None => path_absent(workspace, path),
    }
}

fn package_object(workspace: &Workspace, entry: &SnapshotEntry) -> Result<Vec<u8>, String> {
    let SnapshotEntry::File {
        path,
        sha256,
        bytes,
        asset,
        ..
    } = entry
    else {
        return Err("package pull cannot materialize a non-file object".into());
    };
    let object = safe_path::read_regular(&workspace.store, asset)
        .map_err(|error| format!("cannot read package object for {path}: {error}"))?
        .ok_or_else(|| format!("package object {sha256} is missing"))?;
    if object.len() as u64 != *bytes || format!("{:x}", Sha256::digest(&object)) != *sha256 {
        return Err(format!("package object {sha256} is corrupt"));
    }
    Ok(object)
}

fn cleanup_package_journal(workspace: &Workspace, recovery_dir: &str) -> Result<(), String> {
    let store = SafeDir::open(&workspace.store)
        .map_err(|error| format!("cannot open package recovery store: {error}"))?;
    commands::discard_private_stage(&store, recovery_dir)?;
    store
        .remove_regular(PULL_JOURNAL)
        .map_err(|error| format!("cannot remove package pull journal: {error}"))?;
    Ok(())
}

fn rollback_package_journal(
    workspace: &Workspace,
    journal: &PackagePullJournal,
) -> Result<(), String> {
    let root = SafeDir::open(&workspace.root)
        .map_err(|error| format!("cannot open package workspace for rollback: {error}"))?;
    for operation in journal.operations.iter().rev() {
        let old_matches = coordinate_matches(workspace, &operation.path, operation.old.as_ref())?;
        let new_matches = coordinate_matches(workspace, &operation.path, operation.new.as_ref())?;
        if !old_matches && !new_matches {
            return Err(format!(
                "package recovery refuses changed path {}",
                operation.path
            ));
        }
        match &operation.old {
            Some(old @ SnapshotEntry::File { mode, .. }) if !old_matches => {
                let backup = operation
                    .backup
                    .as_deref()
                    .ok_or_else(|| "package recovery file has no backup".to_string())?;
                let bytes = safe_path::read_regular(
                    &workspace.store,
                    &format!("{}/{backup}", journal.recovery_dir),
                )
                .map_err(|error| format!("cannot read package recovery backup: {error}"))?
                .ok_or_else(|| "package recovery backup is missing".to_string())?;
                if let SnapshotEntry::File {
                    sha256,
                    bytes: expected,
                    ..
                } = old
                {
                    if bytes.len() as u64 != *expected
                        || format!("{:x}", Sha256::digest(&bytes)) != *sha256
                    {
                        return Err("package recovery backup is corrupt".into());
                    }
                }
                root.atomic_write(&operation.path, &bytes, true, *mode)
                    .map_err(|error| format!("cannot restore {}: {error}", operation.path))?;
            }
            None if !old_matches => {
                root.remove_regular(&operation.path)
                    .map_err(|error| format!("cannot roll back {}: {error}", operation.path))?;
            }
            Some(SnapshotEntry::Symlink { .. }) => {
                return Err("package pull journal unexpectedly contains a symlink change".into())
            }
            _ => {}
        }
    }
    write_package_checkout(workspace, &journal.previous)
}

fn recover_package_pull(workspace: &Workspace) -> Result<(), String> {
    let Some(bytes) = safe_path::read_regular(&workspace.store, PULL_JOURNAL)
        .map_err(|error| format!("cannot inspect package pull journal: {error}"))?
    else {
        return Ok(());
    };
    let journal: PackagePullJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("package pull journal is invalid: {error}"))?;
    if journal.version != 1
        || !journal.recovery_dir.starts_with(RECOVERY_PREFIX)
        || journal.operations.is_empty()
        || journal.operations.len() > MAX_FILES
    {
        return Err("package pull journal failed validation".into());
    }
    validate_checkout(&journal.previous, workspace)?;
    validate_checkout(&journal.next, workspace)?;
    let current = read_package_checkout(workspace)?;
    if current.snapshot_root != journal.next.snapshot_root {
        if current.snapshot_root != journal.previous.snapshot_root {
            return Err("package pull journal does not match the checkout receipt".into());
        }
        rollback_package_journal(workspace, &journal)?;
    }
    cleanup_package_journal(workspace, &journal.recovery_dir)
}

fn prepare_package_backups(
    workspace: &Workspace,
    backups: &SafeDir,
    operations: &mut [PackagePullOperation],
) -> Result<(), String> {
    for (index, operation) in operations.iter_mut().enumerate() {
        if let Some(old @ SnapshotEntry::File { path, mode, .. }) = &operation.old {
            let bytes = safe_path::read_regular(&workspace.root, path)
                .map_err(|error| format!("cannot back up package path {path}: {error}"))?
                .ok_or_else(|| format!("package path {path} disappeared before backup"))?;
            if let SnapshotEntry::File {
                sha256,
                bytes: expected,
                ..
            } = old
            {
                if bytes.len() as u64 != *expected
                    || format!("{:x}", Sha256::digest(&bytes)) != *sha256
                {
                    return Err(format!(
                        "package path {path} changed after reconciliation; retry without concurrent edits"
                    ));
                }
            }
            let file = safe_path::open_regular(&workspace.root, path)
                .map_err(|error| format!("cannot inspect package path {path}: {error}"))?
                .ok_or_else(|| format!("package path {path} disappeared before backup"))?;
            if portable_mode(
                &file
                    .metadata()
                    .map_err(|error| format!("cannot inspect package path {path}: {error}"))?,
            ) != *mode
            {
                return Err(format!(
                    "package path {path} mode changed after reconciliation; retry without concurrent edits"
                ));
            }
            let name = format!("{index:08x}.blob");
            backups
                .atomic_create(&name, &bytes, false, 0o600)
                .map_err(|error| format!("cannot write package backup: {error}"))?;
            operation.backup = Some(name);
        }
    }
    Ok(())
}

fn apply_package_delta(
    workspace: &Workspace,
    previous: &PackageCheckout,
    next: &PackageCheckout,
) -> Result<(Vec<String>, Vec<String>), String> {
    if previous.brain != next.brain || previous.profile != next.profile {
        return Err("package pull refuses a brain or profile identity change".into());
    }
    if previous.snapshot_root == next.snapshot_root {
        return Ok((Vec::new(), Vec::new()));
    }
    let old = previous
        .entries
        .iter()
        .map(|entry| (entry.path().to_string(), entry))
        .collect::<BTreeMap<_, _>>();
    let new = next
        .entries
        .iter()
        .map(|entry| (entry.path().to_string(), entry))
        .collect::<BTreeMap<_, _>>();
    let paths = old
        .keys()
        .chain(new.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut operations = Vec::new();
    let mut dirty = Vec::new();
    for path in paths {
        let prior = old.get(&path).copied();
        let remote = new.get(&path).copied();
        if prior == remote {
            if !coordinate_matches(workspace, &path, remote)? {
                dirty.push(path);
            }
            continue;
        }
        if matches!(prior, Some(SnapshotEntry::Symlink { .. }))
            || matches!(remote, Some(SnapshotEntry::Symlink { .. }))
        {
            return Err(format!(
                "package symlink topology changed at {path}; restore into a fresh workspace"
            ));
        }
        if coordinate_matches(workspace, &path, remote)? {
            continue;
        }
        if !coordinate_matches(workspace, &path, prior)? {
            return Err(format!(
                "package pull refuses to overwrite divergent companion {path}"
            ));
        }
        if let Some(entry) = remote {
            package_object(workspace, entry)?;
        }
        operations.push(PackagePullOperation {
            path,
            old: prior.cloned(),
            new: remote.cloned(),
            backup: None,
        });
    }

    if operations.is_empty() {
        write_package_checkout(workspace, next)?;
        return Ok((Vec::new(), dirty));
    }
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| "operating-system randomness unavailable".to_string())?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let recovery_dir = format!("{RECOVERY_PREFIX}{suffix}");
    let store = SafeDir::open(&workspace.store)
        .map_err(|error| format!("cannot open package recovery store: {error}"))?;
    let backups = store
        .create_dir(&recovery_dir, 0o700)
        .map_err(|error| format!("cannot create package recovery directory: {error}"))?;
    if let Err(error) = prepare_package_backups(workspace, &backups, &mut operations) {
        drop(backups);
        commands::discard_private_stage(&store, &recovery_dir)
            .map_err(|cleanup| format!("{error}; package backup cleanup also failed: {cleanup}"))?;
        return Err(error);
    }
    drop(backups);
    let journal = PackagePullJournal {
        version: 1,
        recovery_dir: recovery_dir.clone(),
        previous: previous.clone(),
        next: next.clone(),
        operations,
    };
    let mut journal_bytes = serde_json::to_vec_pretty(&journal)
        .map_err(|error| format!("cannot encode package pull journal: {error}"))?;
    journal_bytes.push(b'\n');
    store
        .atomic_create(PULL_JOURNAL, &journal_bytes, false, 0o600)
        .map_err(|error| format!("cannot write package pull journal: {error}"))?;

    let root = SafeDir::open(&workspace.root)
        .map_err(|error| format!("cannot open package workspace: {error}"))?;
    let applied = (|| -> Result<Vec<String>, String> {
        let mut changed = Vec::new();
        for operation in &journal.operations {
            match &operation.new {
                Some(entry @ SnapshotEntry::File { mode, .. }) => {
                    let bytes = package_object(workspace, entry)?;
                    if !coordinate_matches(workspace, &operation.path, operation.old.as_ref())? {
                        return Err(format!(
                            "package path {} changed immediately before install; no local bytes were overwritten",
                            operation.path
                        ));
                    }
                    root.atomic_write(&operation.path, &bytes, true, *mode)
                        .map_err(|error| {
                            format!("cannot update package path {}: {error}", operation.path)
                        })?;
                }
                None => {
                    if !coordinate_matches(workspace, &operation.path, operation.old.as_ref())? {
                        return Err(format!(
                            "package path {} changed immediately before deletion; no local bytes were overwritten",
                            operation.path
                        ));
                    }
                    root.remove_regular(&operation.path).map_err(|error| {
                        format!("cannot delete package path {}: {error}", operation.path)
                    })?;
                }
                Some(SnapshotEntry::Symlink { .. }) => unreachable!(),
            }
            changed.push(operation.path.clone());
        }
        for operation in &journal.operations {
            if !coordinate_matches(workspace, &operation.path, operation.new.as_ref())? {
                return Err(format!(
                    "package path {} did not verify after install",
                    operation.path
                ));
            }
        }
        write_package_checkout(workspace, next)?;
        Ok(changed)
    })();
    match applied {
        Ok(changed) => {
            cleanup_package_journal(workspace, &recovery_dir)?;
            Ok((changed, dirty))
        }
        Err(error) => {
            rollback_package_journal(workspace, &journal)
                .map_err(|rollback| format!("{error}; package rollback also failed: {rollback}"))?;
            cleanup_package_journal(workspace, &recovery_dir)?;
            Err(error)
        }
    }
}

fn verify_snapshot(
    workspace: &Workspace,
    profile: &str,
    names: Option<&BTreeSet<String>>,
) -> Result<VerifyReport, String> {
    let envelope = load_snapshot(workspace, profile)?;
    let projection_policy = safe_path::open_regular(&workspace.store, ".sevralocal")
        .map_err(|error| format!("cannot inspect package projection policy: {error}"))?;
    let projection_manifest = envelope
        .core
        .projection
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| format!("cannot encode package projection manifest: {error}"))?;
    if projection_policy.is_some() {
        dbmd(
            &workspace.store,
            &["validate", "--all", "--projection-excludes", ".sevralocal"],
            "package brain projection validation",
        )?;
    } else if let Some(manifest) = projection_manifest.as_deref() {
        dbmd_with_input(
            &workspace.store,
            &["validate", "--all", "--projection-manifest", "-"],
            "package brain committed-projection validation",
            Some(manifest),
        )?;
    } else {
        dbmd(
            &workspace.store,
            &["validate", "--all"],
            "package brain validation",
        )?;
    }
    if projection_policy.is_some() {
        dbmd(
            &workspace.store,
            &["assets", "verify", "--projection-excludes", ".sevralocal"],
            "package brain projection asset verification",
        )?;
    } else if let Some(manifest) = projection_manifest.as_deref() {
        dbmd_with_input(
            &workspace.store,
            &["assets", "verify", "--projection-manifest", "-"],
            "package brain committed-projection asset verification",
            Some(manifest),
        )?;
    } else {
        dbmd(
            &workspace.store,
            &["assets", "verify"],
            "package brain asset verification",
        )?;
    }
    let mut missing = Vec::new();
    let mut corrupt = Vec::new();
    let mut bytes = 0_u64;
    let mut files = 0_usize;
    let mut symlinks = 0_usize;
    let mut objects = BTreeSet::new();
    for entry in &envelope.core.entries {
        match entry {
            SnapshotEntry::File {
                path,
                sha256,
                bytes: expected_bytes,
                mode,
                asset,
                ..
            } => {
                files += 1;
                bytes += expected_bytes;
                objects.insert(sha256.clone());
                let object = safe_path::read_regular(&workspace.store, asset)
                    .map_err(|error| format!("cannot read package object for {path}: {error}"))?;
                match object {
                    None => missing.push(format!("object:{sha256}")),
                    Some(data)
                        if data.len() as u64 != *expected_bytes
                            || format!("{:x}", Sha256::digest(&data)) != *sha256 =>
                    {
                        corrupt.push(format!("object:{sha256}"))
                    }
                    Some(_) => {}
                }
                let file = safe_path::open_regular(&workspace.root, path)
                    .map_err(|error| format!("cannot verify restored path {path}: {error}"))?;
                match file {
                    None => missing.push(path.clone()),
                    Some(mut file) => {
                        let mut data = Vec::new();
                        file.read_to_end(&mut data).map_err(|error| {
                            format!("cannot read restored path {path}: {error}")
                        })?;
                        if data.len() as u64 != *expected_bytes
                            || format!("{:x}", Sha256::digest(&data)) != *sha256
                            || portable_mode(
                                &file
                                    .metadata()
                                    .map_err(|error| format!("cannot inspect {path}: {error}"))?,
                            ) != *mode
                        {
                            corrupt.push(path.clone());
                        }
                    }
                }
            }
            SnapshotEntry::Symlink {
                path,
                target,
                target_kind,
            } => {
                symlinks += 1;
                match fs::symlink_metadata(workspace.root.join(path)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        missing.push(path.clone())
                    }
                    Err(error) => {
                        return Err(format!("cannot inspect restored symlink {path}: {error}"))
                    }
                    Ok(metadata) if !metadata.file_type().is_symlink() => {
                        corrupt.push(path.clone())
                    }
                    Ok(_) => match fs::read_link(workspace.root.join(path)) {
                        Ok(actual) if actual == Path::new(target) => {
                            let resolved = lexical_symlink_target(path, target)?;
                            match fs::canonicalize(workspace.root.join(resolved)) {
                                Ok(target) if target.starts_with(&workspace.root) => {
                                    let kind_matches = match target_kind.as_str() {
                                        "file" => target.is_file(),
                                        "directory" => target.is_dir(),
                                        _ => false,
                                    };
                                    if !kind_matches {
                                        corrupt.push(path.clone());
                                    }
                                }
                                _ => corrupt.push(path.clone()),
                            }
                        }
                        Ok(_) => corrupt.push(path.clone()),
                        Err(error) => {
                            return Err(format!("cannot read restored symlink {path}: {error}"))
                        }
                    },
                }
            }
        }
    }
    let current_dependencies = dependency_receipts(
        workspace,
        &envelope
            .core
            .dependencies
            .iter()
            .map(|receipt| DependencySpec {
                id: receipt.id.clone(),
                kind: receipt.kind.clone(),
                required: receipt.required,
                impact: receipt.impact.clone(),
                path: receipt.path.clone(),
                name: receipt.name.clone(),
                locator: receipt.locator.clone(),
                remote: receipt.remote.clone(),
                local_path: receipt.local_path.clone(),
                verification: receipt.verification.clone(),
            })
            .collect::<Vec<_>>(),
        names,
    );
    let mut unresolved_dependencies = Vec::new();
    let mut required_unresolved_dependencies = Vec::new();
    let mut semantic_unresolved_dependencies = Vec::new();
    for (expected, current) in envelope
        .core
        .dependencies
        .iter()
        .zip(current_dependencies.iter())
    {
        let mut resolved = current.status == "resolved";
        if expected.kind == "git" {
            resolved &= current.remote_url == expected.remote_url;
        }
        if !resolved {
            unresolved_dependencies.push(expected.id.clone());
            if expected.required {
                required_unresolved_dependencies.push(expected.id.clone());
            }
            if expected.impact == "semantic" {
                semantic_unresolved_dependencies.push(expected.id.clone());
            }
        }
    }
    missing.sort();
    corrupt.sort();
    let complete =
        missing.is_empty() && corrupt.is_empty() && required_unresolved_dependencies.is_empty();
    let brain_complete = complete && semantic_unresolved_dependencies.is_empty();
    let operational_ready = complete && unresolved_dependencies.is_empty();
    Ok(VerifyReport {
        profile: profile.to_string(),
        snapshot_root: envelope.snapshot_root,
        files,
        symlinks,
        objects: objects.len(),
        bytes,
        missing,
        corrupt,
        unresolved_dependencies,
        required_unresolved_dependencies,
        semantic_unresolved_dependencies,
        brain_complete,
        operational_ready,
        complete,
    })
}

fn restore_entries(workspace: &Workspace, envelope: &SnapshotEnvelope) -> Result<(), String> {
    let root = SafeDir::open(&workspace.root)
        .map_err(|error| format!("cannot securely open restore workspace: {error}"))?;
    for entry in &envelope.core.entries {
        if let SnapshotEntry::File {
            path,
            sha256,
            bytes,
            mode,
            asset,
            ..
        } = entry
        {
            let object = safe_path::read_regular(&workspace.store, asset)
                .map_err(|error| format!("cannot read package object for {path}: {error}"))?
                .ok_or_else(|| format!("package object {sha256} is missing"))?;
            if object.len() as u64 != *bytes || format!("{:x}", Sha256::digest(&object)) != *sha256
            {
                return Err(format!("package object {sha256} is corrupt"));
            }
            if let Some(mut existing) = root
                .open_relative(path)
                .map_err(|error| format!("cannot inspect restore path {path}: {error}"))?
            {
                let mut current = Vec::new();
                existing
                    .read_to_end(&mut current)
                    .map_err(|error| format!("cannot read restore path {path}: {error}"))?;
                if current != object
                    || portable_mode(&existing.metadata().map_err(|e| e.to_string())?) != *mode
                {
                    return Err(format!(
                        "restore refuses to overwrite divergent path {path}"
                    ));
                }
                continue;
            }
            root.atomic_create(path, &object, true, *mode)
                .map_err(|error| format!("cannot restore {path}: {error}"))?;
        }
    }
    for entry in &envelope.core.entries {
        if let SnapshotEntry::Symlink { path, target, .. } = entry {
            lexical_symlink_target(path, target)?;
            match fs::symlink_metadata(workspace.root.join(path)) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let actual = fs::read_link(workspace.root.join(path))
                        .map_err(|error| format!("cannot read existing symlink {path}: {error}"))?;
                    if actual != Path::new(target) {
                        return Err(format!(
                            "restore refuses to replace divergent symlink {path}"
                        ));
                    }
                }
                Ok(_) => return Err(format!("restore refuses to replace existing path {path}")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    safe_path::create_symlink(&workspace.root, path, target)
                        .map_err(|error| format!("cannot restore symlink {path}: {error}"))?;
                }
                Err(error) => return Err(format!("cannot inspect restore path {path}: {error}")),
            }
        }
    }
    Ok(())
}

fn write_vault_names(
    workspace: &Workspace,
    brain: &str,
    names: &BTreeSet<String>,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(&json!({
        "version": 1,
        "brain": brain,
        "names": names,
    }))
    .map_err(|error| format!("cannot encode vault-name receipt: {error}"))?;
    bytes.push(b'\n');
    safe_path::atomic_write(&workspace.store, ".sevra-vault.json", &bytes, false, 0o600)
        .map_err(|error| format!("cannot write vault-name receipt: {error}"))
}

fn fail_restore_stage(
    parent: &SafeDir,
    stage_name: &str,
    message: &str,
    details: Option<Value>,
) -> ! {
    match commands::discard_private_stage(parent, stage_name) {
        Ok(()) => fail(message, details),
        Err(cleanup) => fail(
            &format!("{message}; private restore-stage cleanup also failed: {cleanup}"),
            details,
        ),
    }
}

fn dbmd_help(args: &[&str], capability: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("dbmd").args(args).output().map_err(|error| {
        format!(
            "cannot run db.md CLI capability preflight (install the current dbmd release): {error}"
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "installed db.md CLI does not support {capability}; update dbmd before package restore"
        ));
    }
    Ok(output.stdout)
}

fn require_dbmd_package_capabilities() -> Result<(), String> {
    dbmd_help(
        &["sync", "00000000000000000000000000", "relocate", "--help"],
        "incremental-baseline relocation",
    )?;
    for (args, capability) in [
        (
            &["validate", "--help"][..],
            "projection-aware semantic validation",
        ),
        (
            &["assets", "verify", "--help"][..],
            "projection-aware asset verification",
        ),
    ] {
        let help = dbmd_help(args, capability)?;
        let help = String::from_utf8_lossy(&help);
        if !help.contains("--projection-excludes") || !help.contains("--projection-manifest") {
            return Err(format!(
                "installed db.md CLI does not support {capability}; update dbmd before package restore"
            ));
        }
    }
    Ok(())
}

pub fn restore_command(cfg: &Config, brain: String, workspace_path: String, profile: String) {
    valid_name(&profile, "profile name").unwrap_or_else(|error| fail(&error, None));
    let requested_input = PathBuf::from(&workspace_path);
    if fs::symlink_metadata(&requested_input).is_ok() {
        fail(
            "package restore destination already exists; choose a fresh workspace",
            None,
        );
    }
    let target_name = requested_input
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            fail(
                "package restore destination name is not portable UTF-8",
                None,
            )
        });
    let parent_input = requested_input
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_dbmd_package_capabilities().unwrap_or_else(|error| fail(&error, None));
    safe_path::ensure_dir(parent_input, 0o755).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely create restore parent without following links: {error}"),
            None,
        )
    });
    let parent_path = fs::canonicalize(parent_input)
        .unwrap_or_else(|error| fail(&format!("cannot resolve restore parent: {error}"), None));
    let requested = parent_path.join(target_name);
    if fs::symlink_metadata(&requested).is_ok() {
        fail(
            "package restore destination already exists; choose a fresh workspace",
            None,
        );
    }
    let parent = SafeDir::open(&parent_path).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely hold restore parent: {error}"),
            None,
        )
    });
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .unwrap_or_else(|_| fail("operating-system randomness unavailable", None));
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let stage_name = format!(".sevra-restore-{suffix}");
    let stage_path = parent_path.join(&stage_name);
    let stage = parent
        .create_dir(&stage_name, 0o700)
        .unwrap_or_else(|error| {
            fail(
                &format!("cannot create private restore stage: {error}"),
                None,
            )
        });
    drop(stage);
    let store = stage_path.join("db");
    let (progress_done, progress) = progress_heartbeat(
        &format!(
            "sevra: restoring brain `{}` into a fresh workspace; large asset sets can take several minutes, and the destination stays unpublished until the brain verifies",
            terminal_safe(&brain),
        ),
        "sevra: still downloading and verifying brain content; no scripts or services are being started",
    );
    let sync_result = commands::try_run_dbmd_sync(
        cfg,
        &[
            brain.clone(),
            "--out".into(),
            store.to_string_lossy().into_owned(),
        ],
        &parent_path,
    );
    stop_progress(progress_done, progress);
    let mut sync = match sync_result {
        Ok(value) => value,
        Err(error) => fail_restore_stage(&parent, &stage_name, &error.message, error.details),
    };
    eprintln!("sevra: brain verified; restoring and checking the packaged workspace closure");
    let workspace =
        discover_workspace(stage_path.to_string_lossy().as_ref()).unwrap_or_else(|error| {
            fail_restore_stage(
                &parent,
                &stage_name,
                &format!("brain cloned but workspace is invalid: {error}"),
                Some(sync.clone()),
            )
        });
    let canonical_brain = sync
        .get("brain")
        .or_else(|| sync.get("brain_id"))
        .and_then(Value::as_str)
        .unwrap_or(&brain)
        .to_string();
    commands::write_v2_checkout(&workspace.store, &canonical_brain).unwrap_or_else(|error| {
        fail_restore_stage(
            &parent,
            &stage_name,
            &format!("brain cloned but checkout identity could not be written: {error}"),
            Some(sync.clone()),
        )
    });
    let envelope = load_snapshot(&workspace, &profile).unwrap_or_else(|error| {
        fail_restore_stage(
            &parent,
            &stage_name,
            &format!("brain cloned but package cannot restore: {error}"),
            Some(sync.clone()),
        )
    });
    restore_entries(&workspace, &envelope).unwrap_or_else(|error| {
        fail_restore_stage(
            &parent,
            &stage_name,
            &format!("package restore failed closed: {error}"),
            Some(sync.clone()),
        )
    });
    let names = vault_names(cfg, &brain);
    write_vault_names(&workspace, &canonical_brain, &names).unwrap_or_else(|error| {
        fail_restore_stage(
            &parent,
            &stage_name,
            &format!("package restored but {error}"),
            Some(sync.clone()),
        )
    });
    write_package_checkout(
        &workspace,
        &checkout_from_snapshot(&canonical_brain, &envelope),
    )
    .unwrap_or_else(|error| {
        fail_restore_stage(
            &parent,
            &stage_name,
            &format!("package restored but its incremental receipt failed: {error}"),
            Some(sync.clone()),
        )
    });
    let report = verify_snapshot(&workspace, &profile, Some(&names)).unwrap_or_else(|error| {
        fail_restore_stage(
            &parent,
            &stage_name,
            &format!("package restored but verification failed: {error}"),
            Some(sync.clone()),
        )
    });
    if let Some(object) = sync.as_object_mut() {
        object.insert(
            "package".into(),
            serde_json::to_value(&report).expect("verify report serializes"),
        );
    }
    let human = format!(
        "restored brain and package {} → {}\npackage: {} file(s), {} symlink(s), snapshot {}\ndependencies: {} unresolved ({} required); brain completeness {}; operational readiness {}; no scripts or services were started",
        terminal_safe(&profile),
        terminal_safe(&workspace_path),
        report.files,
        report.symlinks,
        terminal_safe(&report.snapshot_root),
        report.unresolved_dependencies.len(),
        report.required_unresolved_dependencies.len(),
        if report.brain_complete { "established" } else { "not established" },
        if report.operational_ready { "established" } else { "not established" },
    );
    if !report.complete {
        fail_restore_stage(
            &parent,
            &stage_name,
            "package materialized but its required closure did not verify",
            Some(json!({ "package": report, "sync": sync })),
        );
    }
    if let Err(error) = parent.publish_dir_no_replace(&stage_name, target_name) {
        let rollback = commands::discard_private_stage(&parent, &stage_name);
        match rollback {
            Ok(()) => fail(
                &format!(
                    "package restore destination appeared before atomic publish: {error}; private stage was removed"
                ),
                None,
            ),
            Err(rollback_error) => fail(
                &format!(
                    "package restore destination appeared before atomic publish: {error}; private stage cleanup also failed: {rollback_error}"
                ),
                None,
            ),
        }
    }
    let published_store = requested.join("db");
    let relocation = commands::try_run_dbmd_sync(
        cfg,
        &[
            canonical_brain.clone(),
            "relocate".into(),
            "--from".into(),
            store.to_string_lossy().into_owned(),
            "--to".into(),
            published_store.to_string_lossy().into_owned(),
        ],
        &parent_path,
    );
    let relocation = match relocation {
        Ok(value) => value,
        Err(error) => {
            let rollback = parent
                .publish_dir_no_replace(target_name, &stage_name)
                .and_then(|_| {
                    commands::discard_private_stage(&parent, &stage_name)
                        .map_err(std::io::Error::other)
                });
            match rollback {
                Ok(()) => fail(
                    &format!(
                        "package restore could not relocate its incremental sync baseline: {}; the unpublished restore was removed",
                        error.message
                    ),
                    error.details,
                ),
                Err(rollback_error) => fail(
                    &format!(
                        "package restore could not relocate its incremental sync baseline: {}; rollback also failed: {rollback_error}",
                        error.message
                    ),
                    error.details,
                ),
            }
        }
    };
    if let Some(object) = sync.as_object_mut() {
        object.insert("dest".into(), json!(published_store));
        object.insert("workspace".into(), json!(workspace_path));
        object.insert("incrementalBaseline".into(), relocation);
    }
    out_layout(&human, Some(sync));
}

pub fn pull_command(cfg: &Config, workspace_path: String, profile: String) {
    let workspace = discover_workspace(&workspace_path).unwrap_or_else(|error| fail(&error, None));
    let held_store = SafeDir::open(&workspace.store).unwrap_or_else(|error| {
        fail(
            &format!("cannot open package store for locking: {error}"),
            None,
        )
    });
    let _package_lock = held_store
        .lock_relative(PACKAGE_LOCK)
        .unwrap_or_else(|error| {
            fail(
                &format!("cannot lock package lifecycle state: {error}"),
                None,
            )
        });
    recover_package_pull(&workspace).unwrap_or_else(|error| {
        fail(
            &format!("package pull recovery failed closed: {error}"),
            Some(json!({ "code": "package_pull_recovery_failed" })),
        )
    });
    let previous = read_package_checkout(&workspace).unwrap_or_else(|error| {
        fail(
            &error,
            Some(json!({ "code": "package_checkout_receipt_missing" })),
        )
    });
    if previous.profile != profile {
        fail(
            &format!(
                "package checkout tracks profile `{}`, not `{profile}`",
                previous.profile
            ),
            None,
        );
    }
    let (progress_done, progress) = progress_heartbeat(
        "sevra: pulling the verified brain delta and reconciling its signed working closure",
        "sevra: still pulling and verifying the incremental working closure; no scripts or services are being started",
    );
    let mut sync = match commands::try_run_dbmd_sync(
        cfg,
        &[
            previous.brain.clone(),
            "--pull-only".into(),
            "--dir".into(),
            workspace.store.to_string_lossy().into_owned(),
        ],
        &workspace.root,
    ) {
        Ok(value) => value,
        Err(error) => fail(&error.message, error.details),
    };
    let envelope = load_snapshot(&workspace, &profile).unwrap_or_else(|error| {
        fail(
            &format!("brain pulled but package snapshot is invalid: {error}"),
            Some(sync.clone()),
        )
    });
    let names = vault_names(cfg, &previous.brain);
    write_vault_names(&workspace, &previous.brain, &names).unwrap_or_else(|error| {
        fail(
            &format!("brain pulled but vault custody could not be refreshed: {error}"),
            Some(sync.clone()),
        )
    });
    let next = checkout_from_snapshot(&previous.brain, &envelope);
    let (changed, dirty) =
        apply_package_delta(&workspace, &previous, &next).unwrap_or_else(|error| {
            fail(
                &format!("brain pulled but companion reconciliation stopped: {error}"),
                Some(sync.clone()),
            )
        });
    let report = verify_snapshot(&workspace, &profile, Some(&names)).unwrap_or_else(|error| {
        fail(
            &format!("package pull verification failed: {error}"),
            Some(sync.clone()),
        )
    });
    if let Some(object) = sync.as_object_mut() {
        object.insert(
            "package".into(),
            serde_json::to_value(&report).expect("verify report serializes"),
        );
        object.insert("packageChanges".into(), json!(changed));
        object.insert("packageLocalDirty".into(), json!(dirty));
        object.insert("workspace".into(), json!(workspace_path));
    }
    if !report.complete {
        fail(
            "brain pulled, but the companion package is not complete; inspect packageLocalDirty and package verification details",
            Some(sync),
        );
    }
    stop_progress(progress_done, progress);
    out_layout(
        &format!(
            "pulled brain and package {} → {}\ncompanions: {} changed, {} locally divergent; brain completeness {}; operational readiness {}",
            terminal_safe(&profile),
            terminal_safe(&workspace_path),
            changed.len(),
            dirty.len(),
            if report.brain_complete { "established" } else { "not established" },
            if report.operational_ready { "established" } else { "not established" },
        ),
        Some(sync),
    );
}

pub fn verify_command(workspace_path: String, profile: String) {
    let workspace = discover_workspace(&workspace_path).unwrap_or_else(|error| fail(&error, None));
    // Verify the package profile as well as the generated snapshot: an agent
    // must never operate from a valid old snapshot plus an invalid new policy.
    read_profile(&workspace, &profile)
        .unwrap_or_else(|error| fail(&error, Some(json!({ "code": "package_profile_invalid" }))));
    // Offline verification never turns a cached vault-name receipt into live
    // custody evidence. Checkpoint, restore, and pull refresh names from Sevra.
    let report = verify_snapshot(&workspace, &profile, None)
        .unwrap_or_else(|error| fail(&error, Some(json!({ "code": "package_verify_failed" }))));
    if !report.complete {
        fail(
            "package verification found missing, corrupt, or required unresolved state",
            Some(serde_json::to_value(&report).expect("verify report serializes")),
        );
    }
    out_layout(
        &format!(
            "package {} verified: {} file(s), {} symlink(s), snapshot {}\ndependencies: {} unresolved optional; brain completeness {}; operational readiness {}; no scripts or services were started",
            terminal_safe(&report.profile),
            report.files,
            report.symlinks,
            terminal_safe(&report.snapshot_root),
            report.unresolved_dependencies.len(),
            if report.brain_complete { "established" } else { "not established" },
            if report.operational_ready { "established" } else { "not established" },
        ),
        Some(serde_json::to_value(report).expect("verify report serializes")),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlink_targets_may_walk_within_but_never_escape_workspace() {
        assert_eq!(
            lexical_symlink_target(".agents/skills", "../.claude/skills").unwrap(),
            ".claude/skills"
        );
        assert!(lexical_symlink_target("link", "../outside").is_err());
        assert!(lexical_symlink_target("link", "/outside").is_err());
    }

    #[test]
    fn every_restored_symlink_target_belongs_to_the_same_package() {
        let file = SnapshotEntry::File {
            path: ".claude/skills/example/SKILL.md".into(),
            sha256: "a".repeat(64),
            bytes: 1,
            mode: 0o644,
            asset: format!("{OBJECT_PREFIX}/{}.blob", "a".repeat(64)),
            unscanned_binary: false,
        };
        let included = SnapshotEntry::Symlink {
            path: ".agents/skills".into(),
            target: "../.claude/skills".into(),
            target_kind: "directory".into(),
        };
        assert!(validate_symlink_closure(&[file, included]).is_ok());

        let missing = SnapshotEntry::Symlink {
            path: "AGENTS.md".into(),
            target: "CLAUDE.md".into(),
            target_kind: "file".into(),
        };
        assert!(validate_symlink_closure(&[missing]).is_err());
    }

    #[test]
    fn fenced_json_is_exact_and_unambiguous() {
        let good = b"# Profile\n\n```sevra-package-v1\n{\"version\":1,\"profiles\":{}}\n```\n";
        let parsed: PackageConfig = extract_fenced_json(good, PROFILE_FENCE).unwrap();
        assert_eq!(parsed.version, 1);
        let repeated = [good.as_slice(), good.as_slice()].concat();
        assert!(extract_fenced_json::<PackageConfig>(&repeated, PROFILE_FENCE).is_err());
    }

    #[test]
    fn canonical_root_ignores_receipt_timestamp_but_not_content() {
        let core = SnapshotCore {
            version: 1,
            profile: "working".into(),
            profile_sha256: "a".repeat(64),
            store: "db".into(),
            entries: Vec::new(),
            dependencies: Vec::new(),
            projection: None,
        };
        let first = canonical_hash(&core).unwrap();
        let envelope = SnapshotEnvelope {
            version: 1,
            snapshot_root: first.clone(),
            created_at: "2026-01-01T00:00:00Z".into(),
            core,
        };
        assert_eq!(canonical_hash(&envelope.core).unwrap(), first);
    }

    #[test]
    fn private_projection_is_a_sorted_path_commitment_not_a_policy_copy() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("db");
        fs::create_dir_all(store.join("records/private")).unwrap();
        fs::write(store.join(".sevralocal"), "records/private/**\n").unwrap();
        fs::write(store.join("records/private/secret.md"), "private\n").unwrap();
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store,
            store_rel: "db".into(),
        };
        let (manifest, policy_sha256) = build_projection_manifest(&workspace).unwrap().unwrap();
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.algorithm, "sha256");
        assert_eq!(
            manifest.path_hashes,
            vec![projection_path_sha256("records/private/secret.md")]
        );
        let encoded = serde_json::to_string(&manifest).unwrap();
        assert!(!encoded.contains("secret.md"));
        assert!(!encoded.contains("records/private"));
        assert_eq!(
            policy_sha256,
            format!("{:x}", Sha256::digest(b"records/private/**\n"))
        );
        validate_projection_manifest(&manifest).unwrap();
    }

    #[test]
    fn git_remote_receipts_never_preserve_embedded_credentials() {
        assert_eq!(
            safe_git_remote("git@github.com:sevrahq/sevra.git".into()).unwrap(),
            "git@github.com:sevrahq/sevra.git"
        );
        assert!(safe_git_remote("https://token@example.com/private.git".into()).is_err());
        assert!(safe_git_remote("https://user:password@example.com/private.git".into()).is_err());
    }

    #[test]
    fn git_receipt_is_stable_when_the_same_repository_head_moves() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("db")).unwrap();
        for args in [
            vec!["init", "--quiet"],
            vec!["config", "user.name", "Sevra Test"],
            vec!["config", "user.email", "sevra@example.test"],
            vec![
                "remote",
                "add",
                "origin",
                "git@github.com:sevrahq/example.git",
            ],
        ] {
            assert!(Command::new("git")
                .arg("-C")
                .arg(temp.path())
                .args(args)
                .status()
                .unwrap()
                .success());
        }
        fs::write(temp.path().join("first"), "one").unwrap();
        assert!(Command::new("git")
            .arg("-C")
            .arg(temp.path())
            .args(["add", "first"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(temp.path())
            .args(["commit", "--quiet", "-m", "first"])
            .status()
            .unwrap()
            .success());

        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: temp.path().join("db"),
            store_rel: "db".into(),
        };
        let specs = vec![DependencySpec {
            id: "repository-history".into(),
            kind: "git".into(),
            required: false,
            impact: "operational".into(),
            path: Some(".".into()),
            name: None,
            locator: None,
            remote: Some("origin".into()),
            local_path: None,
            verification: None,
        }];
        let first = dependency_receipts(&workspace, &specs, None);

        fs::write(temp.path().join("second"), "two").unwrap();
        assert!(Command::new("git")
            .arg("-C")
            .arg(temp.path())
            .args(["add", "second"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(temp.path())
            .args(["commit", "--quiet", "-m", "second"])
            .status()
            .unwrap()
            .success());
        let second = dependency_receipts(&workspace, &specs, None);

        assert_eq!(
            canonical_hash(&first).unwrap(),
            canonical_hash(&second).unwrap()
        );
    }

    #[test]
    fn checkpoint_can_replace_an_older_generated_snapshot_schema() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("db");
        fs::create_dir_all(store.join("records/operational")).unwrap();
        fs::write(
            store.join(SNAPSHOT_RECORD),
            format!(
                "```{SNAPSHOT_FENCE}\n{{\"snapshot_root\":\"{}\",\"legacy_field\":true}}\n```\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: store.clone(),
            store_rel: "db".into(),
        };

        assert_eq!(
            existing_snapshot_root(&workspace).unwrap(),
            Some("a".repeat(64))
        );
    }

    #[test]
    fn package_delta_updates_only_a_clean_companion_and_advances_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("db");
        let objects = store.join(OBJECT_PREFIX);
        fs::create_dir_all(&objects).unwrap();
        fs::write(
            store.join("DB.md"),
            b"---\ntype: db-md\nscope: company\nowner: test\n---\n",
        )
        .unwrap();
        fs::write(temp.path().join("README.md"), b"old\n").unwrap();
        let old_hash = format!("{:x}", Sha256::digest(b"old\n"));
        let new_hash = format!("{:x}", Sha256::digest(b"new\n"));
        fs::write(objects.join(format!("{new_hash}.blob")), b"new\n").unwrap();
        let entry = |sha256: &str| SnapshotEntry::File {
            path: "README.md".into(),
            sha256: sha256.into(),
            bytes: 4,
            mode: 0o644,
            asset: format!("{OBJECT_PREFIX}/{sha256}.blob"),
            unscanned_binary: false,
        };
        let previous = PackageCheckout {
            version: 1,
            brain: "01m0qwbgagah002c4qg7x1xfcd".into(),
            profile: "working".into(),
            snapshot_root: "a".repeat(64),
            entries: vec![entry(&old_hash)],
        };
        let next = PackageCheckout {
            snapshot_root: "b".repeat(64),
            entries: vec![entry(&new_hash)],
            ..previous.clone()
        };
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: store.clone(),
            store_rel: "db".into(),
        };
        write_package_checkout(&workspace, &previous).unwrap();

        let (changed, dirty) = apply_package_delta(&workspace, &previous, &next).unwrap();
        assert_eq!(changed, vec!["README.md"]);
        assert!(dirty.is_empty());
        assert_eq!(fs::read(temp.path().join("README.md")).unwrap(), b"new\n");
        assert_eq!(
            read_package_checkout(&workspace).unwrap().snapshot_root,
            "b".repeat(64)
        );
        assert!(!store.join(PULL_JOURNAL).exists());
        assert!(fs::read_dir(&workspace.store)
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(RECOVERY_PREFIX)));
    }

    #[test]
    fn package_delta_preserves_a_divergent_companion() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("db");
        let objects = store.join(OBJECT_PREFIX);
        fs::create_dir_all(&objects).unwrap();
        fs::write(
            store.join("DB.md"),
            b"---\ntype: db-md\nscope: company\nowner: test\n---\n",
        )
        .unwrap();
        fs::write(temp.path().join("README.md"), b"local\n").unwrap();
        let old_hash = format!("{:x}", Sha256::digest(b"old\n"));
        let new_hash = format!("{:x}", Sha256::digest(b"new\n"));
        fs::write(objects.join(format!("{new_hash}.blob")), b"new\n").unwrap();
        let entry = |sha256: &str| SnapshotEntry::File {
            path: "README.md".into(),
            sha256: sha256.into(),
            bytes: 4,
            mode: 0o644,
            asset: format!("{OBJECT_PREFIX}/{sha256}.blob"),
            unscanned_binary: false,
        };
        let previous = PackageCheckout {
            version: 1,
            brain: "01m0qwbgagah002c4qg7x1xfcd".into(),
            profile: "working".into(),
            snapshot_root: "a".repeat(64),
            entries: vec![entry(&old_hash)],
        };
        let next = PackageCheckout {
            snapshot_root: "b".repeat(64),
            entries: vec![entry(&new_hash)],
            ..previous.clone()
        };
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store,
            store_rel: "db".into(),
        };
        let error = apply_package_delta(&workspace, &previous, &next).unwrap_err();
        assert!(error.contains("divergent companion README.md"));
        assert_eq!(fs::read(temp.path().join("README.md")).unwrap(), b"local\n");
    }

    #[test]
    fn interrupted_package_pull_recovers_on_both_sides_of_receipt_commit() {
        for receipt_advanced in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = temp.path().join("db");
            let recovery_dir = format!("{RECOVERY_PREFIX}test");
            fs::create_dir_all(store.join(&recovery_dir)).unwrap();
            fs::write(
                store.join("DB.md"),
                b"---\ntype: db-md\nscope: company\nowner: test\n---\n",
            )
            .unwrap();
            fs::write(temp.path().join("README.md"), b"new\n").unwrap();
            fs::write(store.join(&recovery_dir).join("00000000.blob"), b"old\n").unwrap();
            let entry = |bytes: &[u8]| SnapshotEntry::File {
                path: "README.md".into(),
                sha256: format!("{:x}", Sha256::digest(bytes)),
                bytes: bytes.len() as u64,
                mode: 0o644,
                asset: format!("{OBJECT_PREFIX}/{:x}.blob", Sha256::digest(bytes)),
                unscanned_binary: false,
            };
            let previous = PackageCheckout {
                version: 1,
                brain: "01m0qwbgagah002c4qg7x1xfcd".into(),
                profile: "working".into(),
                snapshot_root: "a".repeat(64),
                entries: vec![entry(b"old\n")],
            };
            let next = PackageCheckout {
                snapshot_root: "b".repeat(64),
                entries: vec![entry(b"new\n")],
                ..previous.clone()
            };
            let workspace = Workspace {
                root: temp.path().to_path_buf(),
                store: store.clone(),
                store_rel: "db".into(),
            };
            write_package_checkout(&workspace, if receipt_advanced { &next } else { &previous })
                .unwrap();
            let journal = PackagePullJournal {
                version: 1,
                recovery_dir: recovery_dir.clone(),
                previous: previous.clone(),
                next: next.clone(),
                operations: vec![PackagePullOperation {
                    path: "README.md".into(),
                    old: Some(previous.entries[0].clone()),
                    new: Some(next.entries[0].clone()),
                    backup: Some("00000000.blob".into()),
                }],
            };
            fs::write(
                store.join(PULL_JOURNAL),
                serde_json::to_vec_pretty(&journal).unwrap(),
            )
            .unwrap();

            recover_package_pull(&workspace).unwrap();

            let expected = if receipt_advanced { b"new\n" } else { b"old\n" };
            assert_eq!(fs::read(temp.path().join("README.md")).unwrap(), expected);
            assert_eq!(
                read_package_checkout(&workspace).unwrap().snapshot_root,
                if receipt_advanced {
                    "b".repeat(64)
                } else {
                    "a".repeat(64)
                }
            );
            assert!(!store.join(PULL_JOURNAL).exists());
            assert!(!store.join(recovery_dir).exists());
        }
    }

    fn minimal_profile() -> ProfileSpec {
        ProfileSpec {
            include: vec![IncludeSpec {
                path: "README.md".into(),
                allow_unscanned_binary: false,
            }],
            exclude: Vec::new(),
            allow_secret_named_paths: Vec::new(),
            allow_unscanned_binary_paths: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    fn dummy_file(path: &str) -> SnapshotEntry {
        SnapshotEntry::File {
            path: path.into(),
            sha256: "a".repeat(64),
            bytes: 1,
            mode: 0o644,
            asset: format!("{OBJECT_PREFIX}/{}.blob", "a".repeat(64)),
            unscanned_binary: false,
        }
    }

    fn dummy_envelope(entries: Vec<SnapshotEntry>) -> SnapshotEnvelope {
        SnapshotEnvelope {
            version: 1,
            snapshot_root: "b".repeat(64),
            created_at: "2026-01-01T00:00:00Z".into(),
            core: SnapshotCore {
                version: 1,
                profile: "working".into(),
                profile_sha256: "c".repeat(64),
                store: "db".into(),
                entries,
                dependencies: Vec::new(),
                projection: None,
            },
        }
    }

    #[test]
    fn signed_snapshot_cannot_escape_paths_or_drop_profile_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("db")).unwrap();
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: temp.path().join("db"),
            store_rel: "db".into(),
        };
        let profile = minimal_profile();
        let hostile = dummy_envelope(vec![
            dummy_file("README.md"),
            dummy_file(".git/hooks/post-checkout"),
        ]);
        let error = validate_snapshot_against_profile(&workspace, &profile, &hostile).unwrap_err();
        assert!(error.contains("reserved Git state"));

        let mut dependent = profile;
        dependent.dependencies.push(DependencySpec {
            id: "required-runtime".into(),
            kind: "path".into(),
            required: true,
            impact: "operational".into(),
            path: Some("runtime".into()),
            name: None,
            locator: None,
            remote: None,
            local_path: None,
            verification: Some(PathVerification::Directory {
                allow_empty: false,
                required: vec!["READY".into()],
            }),
        });
        let dropped = dummy_envelope(vec![dummy_file("README.md")]);
        let error =
            validate_snapshot_against_profile(&workspace, &dependent, &dropped).unwrap_err();
        assert!(error.contains("dependency closure"));
    }

    #[test]
    fn dependency_readiness_rejects_placeholders_and_proves_private_closure() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("db");
        fs::create_dir_all(store.join("records/private")).unwrap();
        fs::write(
            store.join("DB.md"),
            "---\ntype: db-md\nscope: test\nowner: test\n---\n",
        )
        .unwrap();
        fs::write(store.join(".sevralocal"), "records/private/secret.md\n").unwrap();
        fs::write(store.join("records/private/secret.md"), "private\n").unwrap();
        fs::create_dir(temp.path().join("empty")).unwrap();
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: store.clone(),
            store_rel: "db".into(),
        };
        let policy_hash = format!(
            "{:x}",
            Sha256::digest(fs::read(store.join(".sevralocal")).unwrap())
        );
        let specs = vec![
            DependencySpec {
                id: "empty-default".into(),
                kind: "path".into(),
                required: false,
                impact: "operational".into(),
                path: Some("empty".into()),
                name: None,
                locator: None,
                remote: None,
                local_path: None,
                verification: None,
            },
            DependencySpec {
                id: "private".into(),
                kind: "path".into(),
                required: false,
                impact: "semantic".into(),
                path: Some("db/.sevralocal".into()),
                name: None,
                locator: None,
                remote: None,
                local_path: None,
                verification: Some(PathVerification::SevralocalClosure {
                    policy_sha256: policy_hash,
                    minimum_entries: 1,
                }),
            },
        ];
        let first = dependency_receipts(&workspace, &specs, None);
        assert_eq!(first[0].status, "unresolved");
        assert_eq!(first[1].status, "resolved");

        fs::remove_file(store.join("records/private/secret.md")).unwrap();
        let second = dependency_receipts(&workspace, &specs, None);
        assert_eq!(second[1].status, "unresolved");
        assert!(second[1]
            .detail
            .as_deref()
            .unwrap()
            .contains("no restored regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_never_resolves_a_path_dependency() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("db")).unwrap();
        symlink("missing", temp.path().join("runtime")).unwrap();
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: temp.path().join("db"),
            store_rel: "db".into(),
        };
        let specs = vec![DependencySpec {
            id: "runtime".into(),
            kind: "path".into(),
            required: false,
            impact: "operational".into(),
            path: Some("runtime".into()),
            name: None,
            locator: None,
            remote: None,
            local_path: None,
            verification: None,
        }];
        let receipt = dependency_receipts(&workspace, &specs, None);
        assert_eq!(receipt[0].status, "unresolved");
    }

    #[test]
    fn package_backup_rechecks_the_old_coordinate_after_selection() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("db");
        fs::create_dir_all(&store).unwrap();
        fs::write(temp.path().join("README.md"), b"edited\n").unwrap();
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: store.clone(),
            store_rel: "db".into(),
        };
        let old = SnapshotEntry::File {
            path: "README.md".into(),
            sha256: format!("{:x}", Sha256::digest(b"old\n")),
            bytes: 4,
            mode: 0o644,
            asset: format!("{OBJECT_PREFIX}/{}.blob", "a".repeat(64)),
            unscanned_binary: false,
        };
        let mut operations = vec![PackagePullOperation {
            path: "README.md".into(),
            old: Some(old),
            new: None,
            backup: None,
        }];
        let root = SafeDir::open(&store).unwrap();
        let backups = root.create_dir("backups", 0o700).unwrap();
        let error = prepare_package_backups(&workspace, &backups, &mut operations).unwrap_err();
        assert!(error.contains("changed after reconciliation"));
        assert_eq!(
            fs::read(temp.path().join("README.md")).unwrap(),
            b"edited\n"
        );
    }

    #[test]
    fn binary_exceptions_are_exact_and_generated_caches_are_never_packages() {
        let mut profile = minimal_profile();
        profile.include[0].path = ".claude/skills".into();
        profile.allow_unscanned_binary_paths = vec![".claude/skills/report/reference.pdf".into()];
        assert!(validate_profile(&profile).is_ok());
        assert!(binary_allowed_for_path(
            &profile,
            ".claude/skills/report/reference.pdf"
        ));
        assert!(!binary_allowed_for_path(
            &profile,
            ".claude/skills/report/other.pdf"
        ));
        assert!(generated_cache_path(
            ".claude/skills/video/__pycache__/core.cpython-312.pyc"
        ));

        profile.include[0].allow_unscanned_binary = true;
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("db")).unwrap();
        fs::create_dir_all(temp.path().join(".claude/skills")).unwrap();
        fs::write(temp.path().join(".claude/skills/SKILL.md"), "ok\n").unwrap();
        let workspace = Workspace {
            root: temp.path().to_path_buf(),
            store: temp.path().join("db"),
            store_rel: "db".into(),
        };
        let mut collected = Collected::default();
        let error = collect_include(
            &workspace,
            &profile.include[0],
            &[],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &mut collected,
        )
        .unwrap_err();
        assert!(error.contains("directory-wide binary exception"));
    }
}
