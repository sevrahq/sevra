//! Asset byte transport — the client half of "dbmd owns the manifest, the hub
//! owns the bytes".
//!
//! A pushed snapshot carries `assets.jsonl` (the manifest `dbmd assets scan`
//! maintains: store-relative path, content SHA-256, byte count) but never the
//! binary bytes themselves — packs are markdown-only by design. After a
//! committed push, [`sync_after_push`] asks the hub which declared hashes are
//! still missing and ships each one through the content-addressed flow:
//! presign (quota-reserved) → exact-length checksummed PUT → confirm. Blobs
//! dedupe on hash, re-pushes skip everything already present, and
//! `.sevralocal` kept-home paths never leave the machine. [`restore_assets`]
//! is the inverse for `sevra export`: every manifest entry missing (or
//! drifted) beside the exported store is fetched, SHA-verified, and written
//! under the export root.
//!
//! Push order matters and is enforced hub-side: a hash can only be uploaded
//! once the manifest naming it has been ingested (`undeclared_asset`
//! otherwise), which is why sync runs strictly AFTER the snapshot commit.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::commands::{contained, human_size};
use crate::config::Config;
use crate::hub::{ensure_ok, get_presigned_to_writer, put_presigned_file, request};
use crate::local::LocalScope;
use crate::output::{fail, note};

/// The hub's official per-asset ceiling. This is a client-owned bound too:
/// neither a hostile manifest nor a compromised hub may make the CLI allocate
/// or stream an unbounded object.
const MAX_ASSET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Secret inspection is deliberately bounded independently of the transport
/// ceiling. Assets above this size still use the streaming, checksummed
/// transport, but the CLI says plainly that their content was not inspected.
const MAX_ASSET_SECRET_SCAN_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ASSET_SECRET_SCAN_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

fn reject_symlink_components(root: &Path, rel: &str) -> Result<(), String> {
    let mut current = root.to_path_buf();
    for component in Path::new(rel).components() {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|_| "asset path component is missing".to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("asset path must not contain symlinks".into());
        }
    }
    Ok(())
}

fn open_asset_source(root: &Path, rel: &str) -> Result<File, String> {
    if contained(root, rel).is_none() {
        return Err("path is not store-relative".into());
    }
    // This early inspection gives a precise operator message for a static
    // malicious tree. `safe_path::open_regular` is the actual boundary: on
    // Unix it traverses through held dirfds with O_NOFOLLOW and reads the held
    // leaf descriptor, so a swap after this check cannot redirect the read.
    reject_symlink_components(root, rel)?;
    let secure_root =
        std::fs::canonicalize(root).map_err(|e| format!("store root cannot be resolved: {e}"))?;
    crate::safe_path::open_regular(&secure_root, rel)
        .map_err(|e| format!("asset source cannot be opened safely: {e}"))?
        .ok_or_else(|| "file is missing".to_string())
}

#[derive(Debug)]
struct AssetStage {
    file: File,
    path: PathBuf,
}

impl AssetStage {
    fn create() -> Result<Self, String> {
        for _ in 0..16 {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| "operating-system randomness unavailable".to_string())?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("sevra-asset-{suffix}"));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => return Ok(Self { file, path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("asset stage could not be created: {error}")),
            }
        }
        Err("asset stage name collided repeatedly".into())
    }
}

impl Drop for AssetStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Copy one held no-follow source into a bounded private stage while hashing.
/// `Ok(None)` means the local bytes drifted from the manifest.
fn stage_asset_source(
    root: &Path,
    rel: &str,
    declared_bytes: u64,
    expected_sha256: &str,
) -> Result<Option<AssetStage>, String> {
    if declared_bytes > MAX_ASSET_BYTES {
        return Err(format!(
            "manifest size exceeds the {} GiB client asset limit",
            MAX_ASSET_BYTES / (1024 * 1024 * 1024)
        ));
    }
    let mut source = open_asset_source(root, rel)?;
    let metadata = source
        .metadata()
        .map_err(|error| format!("asset source metadata could not be read: {error}"))?;
    // This catches sparse bombs from logical length alone, before a single
    // data byte is read.
    if metadata.len() > MAX_ASSET_BYTES {
        return Err(format!(
            "local file exceeds the {} GiB client asset limit",
            MAX_ASSET_BYTES / (1024 * 1024 * 1024)
        ));
    }
    if metadata.len() != declared_bytes {
        return Ok(None);
    }

    let mut stage = AssetStage::create()?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| format!("asset source read failed: {error}"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > declared_bytes || total > MAX_ASSET_BYTES {
            return Ok(None);
        }
        hasher.update(&buffer[..count]);
        stage
            .file
            .write_all(&buffer[..count])
            .map_err(|error| format!("asset stage write failed: {error}"))?;
    }
    if total != declared_bytes || format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Ok(None);
    }
    stage
        .file
        .sync_all()
        .map_err(|error| format!("asset stage sync failed: {error}"))?;
    stage
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("asset stage rewind failed: {error}"))?;
    Ok(Some(stage))
}

fn held_file_matches(mut file: File, bytes: u64, sha256: &str) -> bool {
    if bytes > MAX_ASSET_BYTES {
        return false;
    }
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if metadata.len() != bytes || metadata.len() > MAX_ASSET_BYTES {
        return false;
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let Ok(count) = file.read(&mut buffer) else {
            return false;
        };
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > bytes {
            return false;
        }
        hasher.update(&buffer[..count]);
    }
    total == bytes && format!("{:x}", hasher.finalize()) == sha256
}

/// Refuse a symlink already present before the network download. This is an
/// early/no-I/O courtesy, not the write boundary; the final install runs
/// through `safe_path::atomic_write_with`, which repeats traversal through held
/// handles and atomically replaces the leaf without following it.
#[cfg(test)]
fn preflight_asset_destination(root: &Path, rel: &str) -> Result<(), String> {
    if contained(root, rel).is_none() {
        return Err("path is not export-relative".into());
    }
    let mut current = root.to_path_buf();
    let parts: Vec<_> = Path::new(rel).components().collect();
    for (index, component) in parts.iter().enumerate() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(if index + 1 == parts.len() {
                        "asset leaf is a symlink".into()
                    } else {
                        "asset parent must not contain symlinks".into()
                    });
                }
                if index + 1 != parts.len() && !metadata.is_dir() {
                    return Err("asset parent component is not a directory".into());
                }
                if index + 1 == parts.len() && !metadata.is_file() {
                    return Err("asset destination is not a regular file".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!("asset parent cannot be inspected: {error}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn write_asset_destination(root: &Path, rel: &str, data: &[u8]) -> Result<(), String> {
    if contained(root, rel).is_none() {
        return Err("path is not export-relative".into());
    }
    crate::safe_path::atomic_write(root, rel, data, true, 0o644)
        .map_err(|e| format!("asset could not be safely installed: {e}"))
}

/// One missing-asset row from `GET /assets?status=missing`.
struct MissingAsset {
    path: String,
    sha256: String,
    bytes: u64,
}

/// What a post-push sync did, for the push summary (human + JSON).
pub struct SyncReport {
    pub uploaded: usize,
    pub uploaded_bytes: u64,
    pub already_present: usize,
    pub kept_home: usize,
    pub missing_local: usize,
    pub drifted: usize,
}

impl SyncReport {
    pub fn to_json(&self) -> Value {
        json!({
            "uploaded": self.uploaded,
            "uploadedBytes": self.uploaded_bytes,
            "alreadyPresent": self.already_present,
            "keptHome": self.kept_home,
            "missingLocal": self.missing_local,
            "drifted": self.drifted,
        })
    }
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn missing_assets(cfg: &Config, brain: &str) -> (Vec<MissingAsset>, bool) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/assets?status=missing", enc(brain)),
            None,
            true,
        ),
        "list missing assets",
    );
    let rows = r
        .get("assets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let truncated = r.get("truncated").and_then(Value::as_bool).unwrap_or(false);
    let assets =
        rows.iter()
            .filter_map(|row| {
                let path = row.get("path")?.as_str()?.to_string();
                let sha256 = row.get("sha256")?.as_str()?.to_string();
                let bytes = row.get("bytes")?.as_u64()?;
                (sha256.len() == 64 && sha256.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .then_some(MissingAsset {
                        path,
                        sha256,
                        bytes,
                    })
            })
            .collect();
    (assets, truncated)
}

/// Upload every blob the hub reports missing for `brain`, reading each from
/// its manifest path under `dir`. Returns the tally; hard-fails only on hub
/// contract errors (a refused presign that is not `already_present`, a failed
/// confirm) — a locally missing or drifted file is reported and skipped, so
/// one stale manifest row cannot strand the rest of the store's bytes.
pub fn sync_after_push(
    cfg: &Config,
    brain: &str,
    dir: &str,
    scope: Option<&LocalScope>,
) -> SyncReport {
    let root = Path::new(dir);
    let mut report = SyncReport {
        uploaded: 0,
        uploaded_bytes: 0,
        already_present: 0,
        kept_home: 0,
        missing_local: 0,
        drifted: 0,
    };

    // The missing set only shrinks as confirms land, so a truncated first
    // page converges by re-asking. Bounded: a page that uploads nothing new
    // ends the loop (every remaining row was skipped as kept-home/missing).
    loop {
        let (missing, truncated) = missing_assets(cfg, brain);
        if missing.is_empty() {
            break;
        }

        // Dedupe by hash — two manifest paths with identical bytes need one
        // upload. Every path is a candidate read location for its hash.
        let mut by_sha: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
        for m in missing {
            let entry = by_sha.entry(m.sha256).or_insert((m.bytes, Vec::new()));
            entry.1.push(m.path);
        }

        let mut progressed = false;
        for (sha256, (declared_bytes, paths)) in &by_sha {
            if *declared_bytes > MAX_ASSET_BYTES {
                note(&format!(
                    "refusing asset {}: manifest size exceeds the {} GiB client limit",
                    paths.first().map(String::as_str).unwrap_or(sha256),
                    MAX_ASSET_BYTES / (1024 * 1024 * 1024)
                ));
                report.drifted += 1;
                continue;
            }
            // Find a readable, non-kept-home copy whose bytes still match the
            // manifest. A drifted file (edited since `dbmd assets scan`) is
            // named and skipped — re-scan and push again to update the
            // declaration.
            let mut staged: Option<AssetStage> = None;
            let mut kept = 0usize;
            let mut absent = 0usize;
            for path in paths {
                if scope.is_some_and(|s| s.keeps_home(path)) {
                    kept += 1;
                    continue;
                }
                let candidate = match stage_asset_source(root, path, *declared_bytes, sha256) {
                    Ok(candidate) => candidate,
                    Err(reason) => {
                        note(&format!("refusing asset source {path}: {reason}"));
                        absent += 1;
                        continue;
                    }
                };
                if let Some(candidate) = candidate {
                    staged = Some(candidate);
                    break;
                }
                note(&format!(
                    "asset {path} drifted since `dbmd assets scan` (bytes or hash changed) — re-scan and push to update the manifest"
                ));
                report.drifted += 1;
            }
            let Some(staged) = staged else {
                if kept > 0 && kept == paths.len() {
                    report.kept_home += kept;
                } else if report.drifted == 0 || absent > 0 {
                    report.missing_local += absent.max(1);
                    note(&format!(
                        "asset bytes for {} not found locally ({}) — the manifest names them, the hub still lacks them",
                        &sha256[..12],
                        paths.join(", ")
                    ));
                }
                continue;
            };

            let presigned = ensure_ok(
                request(
                    cfg,
                    "GET",
                    &format!(
                        "/api/hub/brains/{}/assets/presign?sha256={}&action=put",
                        enc(brain),
                        sha256
                    ),
                    None,
                    true,
                ),
                "prepare asset upload",
            );
            if presigned
                .get("alreadyPresent")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                report.already_present += 1;
                progressed = true;
                continue;
            }
            let url = presigned
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_else(|| fail("hub returned no asset upload URL", None));
            let reservation_id = presigned
                .get("reservationId")
                .and_then(Value::as_str)
                .unwrap_or_else(|| fail("hub returned no asset reservation id", None));
            put_presigned_file(
                cfg,
                url,
                presigned.get("headers").unwrap_or(&Value::Null),
                &staged.file,
                *declared_bytes,
            );
            ensure_ok(
                request(
                    cfg,
                    "POST",
                    &format!("/api/hub/brains/{}/assets/confirm", enc(brain)),
                    Some(&json!({ "sha256": sha256, "reservationId": reservation_id })),
                    true,
                ),
                "confirm asset upload",
            );
            note(&format!(
                "asset {} uploaded ({})",
                paths.first().map(String::as_str).unwrap_or(sha256),
                human_size(*declared_bytes)
            ));
            report.uploaded += 1;
            report.uploaded_bytes += *declared_bytes;
            progressed = true;
        }

        if !truncated || !progressed {
            break;
        }
    }
    report
}

const MAX_MANIFEST_LINES: usize = 100_000;

#[derive(Clone, Debug)]
pub struct AssetDeclaration {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Parse the hosted manifest as untrusted input before the export root is
/// touched. A malformed row cannot be silently skipped: that would make a
/// successful export omit bytes the store explicitly declares.
pub fn parse_restore_manifest(manifest: Option<&[u8]>) -> Result<Vec<AssetDeclaration>, String> {
    let Some(manifest) = manifest else {
        return Ok(Vec::new());
    };
    let manifest =
        std::str::from_utf8(manifest).map_err(|_| "assets.jsonl is not valid UTF-8".to_string())?;
    if manifest.lines().count() > MAX_MANIFEST_LINES {
        return Err(format!(
            "assets.jsonl has more than {MAX_MANIFEST_LINES} lines"
        ));
    }

    let mut declarations = Vec::new();
    for (index, raw) in manifest.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(line)
            .map_err(|_| format!("assets.jsonl line {} is not valid JSON", index + 1))?;
        let path = entry
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("assets.jsonl line {} has no path", index + 1))?;
        crate::commands::validate_portable_asset_path(path)
            .map_err(|reason| format!("assets.jsonl line {}: {reason}", index + 1))?;
        let sha256 = entry
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| format!("assets.jsonl line {} has an invalid sha256", index + 1))?;
        if sha256.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(format!(
                "assets.jsonl line {} has a non-canonical sha256",
                index + 1
            ));
        }
        let bytes = entry
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("assets.jsonl line {} has invalid bytes", index + 1))?;
        if bytes > MAX_ASSET_BYTES {
            return Err(format!(
                "assets.jsonl line {} exceeds the {} GiB client asset limit",
                index + 1,
                MAX_ASSET_BYTES / (1024 * 1024 * 1024)
            ));
        }
        declarations.push(AssetDeclaration {
            path: path.to_string(),
            sha256: sha256.to_string(),
            bytes,
        });
    }
    Ok(declarations)
}

/// Coverage and omissions from the pre-upload asset secret gate. Counters are
/// surfaced in both human and JSON output so a bounded scan is never mistaken
/// for universal binary inspection.
#[derive(Default)]
pub struct AssetSecretScanReport {
    pub hits: Vec<crate::scan::SecretHit>,
    pub inspected: usize,
    pub inspected_bytes: u64,
    pub kept_home: usize,
    pub skipped_too_large: usize,
    pub skipped_budget: usize,
    pub skipped_non_utf8: usize,
    pub skipped_unavailable: usize,
    pub skipped_drifted: usize,
    pub invalid_manifest_rows: usize,
}

impl AssetSecretScanReport {
    pub fn skipped(&self) -> usize {
        self.skipped_too_large
            + self.skipped_budget
            + self.skipped_non_utf8
            + self.skipped_unavailable
            + self.skipped_drifted
            + self.invalid_manifest_rows
    }

    pub fn coverage_note(&self) -> Option<String> {
        if self.skipped() == 0 && self.kept_home == 0 {
            return None;
        }
        Some(format!(
            "asset secret scan inspected {} text asset(s); not inspected: {} over {} MiB, {} beyond the {} MiB total budget, {} binary/non-UTF-8, {} missing/unsafe, {} drifted, {} invalid manifest row(s); {} kept home by .sevralocal",
            self.inspected,
            self.skipped_too_large,
            MAX_ASSET_SECRET_SCAN_BYTES / (1024 * 1024),
            self.skipped_budget,
            MAX_ASSET_SECRET_SCAN_TOTAL_BYTES / (1024 * 1024),
            self.skipped_non_utf8,
            self.skipped_unavailable,
            self.skipped_drifted,
            self.invalid_manifest_rows,
            self.kept_home,
        ))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "inspected": self.inspected,
            "inspectedBytes": self.inspected_bytes,
            "keptHome": self.kept_home,
            "skipped": {
                "tooLarge": self.skipped_too_large,
                "totalBudget": self.skipped_budget,
                "nonUtf8": self.skipped_non_utf8,
                "unavailable": self.skipped_unavailable,
                "drifted": self.skipped_drifted,
                "invalidManifestRows": self.invalid_manifest_rows,
            },
            "maxInspectedBytes": MAX_ASSET_SECRET_SCAN_BYTES,
            "maxTotalInspectedBytes": MAX_ASSET_SECRET_SCAN_TOTAL_BYTES,
        })
    }
}

/// Parse the valid declaration rows for the scan without turning an unrelated
/// malformed row into a claim that no other asset was inspected. The hub does
/// not upload malformed declarations; they are counted explicitly instead.
fn scan_declarations(manifest: Option<&str>) -> (Vec<AssetDeclaration>, usize) {
    let Some(manifest) = manifest else {
        return (Vec::new(), 0);
    };
    let mut declarations = Vec::new();
    let mut invalid = 0usize;
    for (index, raw) in manifest.lines().enumerate() {
        if index >= MAX_MANIFEST_LINES {
            invalid += 1;
            continue;
        }
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some((path, sha256, bytes)) =
            serde_json::from_str::<Value>(line).ok().and_then(|entry| {
                let path = entry.get("path")?.as_str()?.to_string();
                let sha256 = entry.get("sha256")?.as_str()?.to_string();
                let bytes = entry.get("bytes")?.as_u64()?;
                Some((path, sha256, bytes))
            })
        else {
            invalid += 1;
            continue;
        };
        let valid_sha = sha256.len() == 64
            && sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if crate::commands::validate_portable_asset_path(&path).is_err()
            || !valid_sha
            || bytes > MAX_ASSET_BYTES
        {
            invalid += 1;
            continue;
        }
        declarations.push(AssetDeclaration {
            path,
            sha256,
            bytes,
        });
    }
    (declarations, invalid)
}

/// Scan the exact local bytes named by the pushed asset manifest. The held
/// descriptor, manifest length, and SHA bind inspection to the same immutable
/// content identity the upload path accepts. Missing, drifted, non-UTF-8, and
/// oversized inputs are never silently treated as scanned.
pub fn scan_declared_asset_secrets(
    dir: &str,
    manifest: Option<&str>,
    scope: Option<&LocalScope>,
    include_kept_home: bool,
) -> AssetSecretScanReport {
    let (declarations, invalid_manifest_rows) = scan_declarations(manifest);
    let mut report = AssetSecretScanReport {
        invalid_manifest_rows,
        ..AssetSecretScanReport::default()
    };
    let root = Path::new(dir);
    let mut scan_budget_used = 0_u64;

    for declaration in declarations {
        if !include_kept_home && scope.is_some_and(|s| s.keeps_home(&declaration.path)) {
            report.kept_home += 1;
            continue;
        }
        report
            .hits
            .extend(crate::scan::scan_path(&declaration.path));

        let mut file = match open_asset_source(root, &declaration.path) {
            Ok(file) => file,
            Err(_) => {
                report.skipped_unavailable += 1;
                continue;
            }
        };
        let Ok(metadata) = file.metadata() else {
            report.skipped_unavailable += 1;
            continue;
        };
        if metadata.len() != declaration.bytes {
            report.skipped_drifted += 1;
            continue;
        }
        if metadata.len() > MAX_ASSET_SECRET_SCAN_BYTES {
            report.skipped_too_large += 1;
            continue;
        }
        if scan_budget_used.saturating_add(metadata.len()) > MAX_ASSET_SECRET_SCAN_TOTAL_BYTES {
            report.skipped_budget += 1;
            continue;
        }
        scan_budget_used += metadata.len();

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        if Read::by_ref(&mut file)
            .take(MAX_ASSET_SECRET_SCAN_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 != declaration.bytes
            || format!("{:x}", Sha256::digest(&bytes)) != declaration.sha256
        {
            report.skipped_drifted += 1;
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            report.skipped_non_utf8 += 1;
            continue;
        };
        report.inspected += 1;
        report.inspected_bytes += bytes.len() as u64;
        report
            .hits
            .extend(crate::scan::scan_content(&declaration.path, text));
    }
    report
}

pub struct PreparedAsset {
    path: String,
    bytes: u64,
    sha256: String,
    stage: AssetStage,
}

impl PreparedAsset {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn write_to(&mut self, destination: &mut File) -> io::Result<()> {
        self.stage.file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = self.stage.file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied.checked_add(count as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "asset stage length overflow")
            })?;
            if copied > self.bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "verified asset stage grew before commit",
                ));
            }
            destination.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
        }
        if copied != self.bytes {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "verified asset stage changed length before commit",
            ));
        }
        if format!("{:x}", hasher.finalize()) != self.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verified asset stage changed hash before commit",
            ));
        }
        Ok(())
    }
}

pub struct PreparedRestore {
    assets: Vec<PreparedAsset>,
    present: usize,
}

impl PreparedRestore {
    pub fn assets_mut(&mut self) -> &mut [PreparedAsset] {
        &mut self.assets
    }

    pub fn report(&self) -> RestoreReport {
        RestoreReport {
            restored: self.assets.len(),
            restored_bytes: self.assets.iter().map(|asset| asset.bytes).sum(),
            present: self.present,
            failed: 0,
        }
    }
}

fn download_asset_stage(
    cfg: &Config,
    brain: &str,
    declaration: &AssetDeclaration,
) -> Result<AssetStage, String> {
    let presigned = ensure_ok(
        request(
            cfg,
            "GET",
            &format!(
                "/api/hub/brains/{}/assets/presign?sha256={}&action=get",
                enc(brain),
                declaration.sha256
            ),
            None,
            true,
        ),
        "prepare asset download",
    );
    let url = presigned
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("hub returned no download URL for {}", declaration.path))?;
    let mut stage = AssetStage::create()?;
    let mut hasher = Sha256::new();
    let mut hashing_writer = HashingWriter {
        inner: &mut stage.file,
        hasher: &mut hasher,
    };
    let downloaded = get_presigned_to_writer(cfg, url, &mut hashing_writer, declaration.bytes)
        .map_err(|error| format!("could not restore asset {}: {error}", declaration.path))?;
    if downloaded != declaration.bytes {
        return Err(format!(
            "downloaded length disagrees with the manifest for {}",
            declaration.path
        ));
    }
    if format!("{:x}", hasher.finalize()) != declaration.sha256 {
        return Err(format!(
            "downloaded bytes failed SHA-256 verification for {}",
            declaration.path
        ));
    }
    stage
        .file
        .sync_all()
        .map_err(|error| format!("asset stage sync failed: {error}"))?;
    stage
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("asset stage rewind failed: {error}"))?;
    Ok(stage)
}

/// Stage every missing asset before the first exported file is changed. The
/// caller then commits these held stages together with the store entries under
/// one held export-root capability.
pub fn prepare_restore(
    cfg: &Config,
    brain: &str,
    root: Option<&crate::safe_path::SafeDir>,
    declarations: &[AssetDeclaration],
) -> Result<PreparedRestore, String> {
    let mut assets = Vec::new();
    let mut present = 0usize;
    for declaration in declarations {
        if let Some(root) = root {
            match root.open_relative(&declaration.path) {
                Ok(Some(file)) => {
                    if held_file_matches(file, declaration.bytes, &declaration.sha256) {
                        present += 1;
                        continue;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(format!(
                        "refusing unsafe asset destination {}: {error}",
                        declaration.path
                    ));
                }
            }
        }
        assets.push(PreparedAsset {
            path: declaration.path.clone(),
            bytes: declaration.bytes,
            sha256: declaration.sha256.clone(),
            stage: download_asset_stage(cfg, brain, declaration)?,
        });
    }
    Ok(PreparedRestore { assets, present })
}

/// What an export-side restore did, for the export summary.
pub struct RestoreReport {
    pub restored: usize,
    pub restored_bytes: u64,
    pub present: usize,
    pub failed: usize,
}

impl RestoreReport {
    pub fn to_json(&self) -> Value {
        json!({
            "restored": self.restored,
            "restoredBytes": self.restored_bytes,
            "present": self.present,
            "failed": self.failed,
        })
    }
}

struct HashingWriter<'a, W> {
    inner: &'a mut W,
    hasher: &'a mut Sha256,
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        open_asset_source, parse_restore_manifest, preflight_asset_destination, stage_asset_source,
        write_asset_destination, AssetStage, PreparedAsset, MAX_ASSET_BYTES,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{Seek, SeekFrom, Write};

    #[cfg(unix)]
    #[test]
    fn asset_source_and_destination_refuse_external_symlinks() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = t.path().join("outside");
        fs::write(&outside, b"do not read or replace").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("asset.bin")).unwrap();

        assert!(open_asset_source(&root, "asset.bin")
            .unwrap_err()
            .contains("symlink"));
        assert!(preflight_asset_destination(&root, "asset.bin")
            .unwrap_err()
            .contains("symlink"));
        assert_eq!(fs::read(&outside).unwrap(), b"do not read or replace");
    }

    #[cfg(unix)]
    #[test]
    fn asset_source_refuses_a_contained_ancestor_symlink() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("asset.bin"), b"private bytes").unwrap();
        std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();

        assert!(open_asset_source(&root, "alias/asset.bin")
            .unwrap_err()
            .contains("must not contain symlinks"));
    }

    #[cfg(unix)]
    #[test]
    fn asset_destination_does_not_create_through_an_ancestor_symlink() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let outside = t.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("alias")).unwrap();

        assert!(preflight_asset_destination(&root, "alias/new/asset.bin")
            .unwrap_err()
            .contains("must not contain symlinks"));
        assert!(!outside.join("new").exists());
    }

    #[test]
    fn staged_asset_replaces_a_regular_file() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let path = root.join("asset.bin");
        fs::write(&path, b"old").unwrap();
        write_asset_destination(&root, "asset.bin", b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn sparse_oversize_source_is_refused_from_metadata_before_reading() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let path = root.join("asset.bin");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_ASSET_BYTES + 1).unwrap();
        drop(file);

        let error = stage_asset_source(&root, "asset.bin", 4, "0".repeat(64).as_str()).unwrap_err();
        assert!(error.contains("local file exceeds"));
        assert_eq!(fs::metadata(path).unwrap().len(), MAX_ASSET_BYTES + 1);
    }

    #[test]
    fn prepared_asset_rehashes_same_length_stage_bytes_at_commit() {
        let original = b"trusted";
        let tampered = b"mutated";
        assert_eq!(original.len(), tampered.len());
        let mut stage = AssetStage::create().unwrap();
        stage.file.write_all(original).unwrap();
        stage.file.sync_all().unwrap();
        let mut prepared = PreparedAsset {
            path: "_files/example.bin".to_string(),
            bytes: original.len() as u64,
            sha256: format!("{:x}", Sha256::digest(original)),
            stage,
        };

        // Model a same-user process finding and replacing the private temp
        // bytes after download verification but before export commit.
        prepared.stage.file.seek(SeekFrom::Start(0)).unwrap();
        prepared.stage.file.write_all(tampered).unwrap();
        prepared.stage.file.sync_all().unwrap();

        let mut destination = tempfile::tempfile().unwrap();
        let error = prepared.write_to(&mut destination).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("changed hash"));
    }

    #[test]
    fn restore_manifest_is_fail_closed_and_reserves_control_paths() {
        let sha = "a".repeat(64);
        for path in [
            "Assets.jsonl",
            ".sevralocal",
            "DB.MD",
            "feed/object.bin",
            "COM¹.bin",
            "trailing.",
        ] {
            let row = format!(r#"{{"path":"{path}","sha256":"{sha}","bytes":1}}"#);
            assert!(
                parse_restore_manifest(Some(row.as_bytes())).is_err(),
                "must reject {path}"
            );
        }
        assert!(parse_restore_manifest(Some(b"{not-json\n")).is_err());
        assert!(
            parse_restore_manifest(Some(br#"{"path":"files/a.bin","sha256":"AA","bytes":1}"#))
                .is_err()
        );
    }
}
