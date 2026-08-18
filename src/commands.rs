//! The command handlers — full parity with the retired TS CLI, including the
//! quality-pass behaviors (env-blind login, https-only hubs, non-JSON refusal,
//! symlink-contained bounded push, export path containment + slug
//! validation, gated-page reporting). `validate` shells `dbmd` and never links
//! its library — Sevra's product tool consumes the standard through the same
//! public binary any third party gets.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::config::{self, Config, DEFAULT_HUB};
use crate::hub::{
    ensure_ok, get_presigned, put_presigned, request, request_with_timeout, HubResponse,
    NOT_LOGGED_IN,
};
use crate::local;
use crate::output::{fail, json_mode, note, out, out_layout, terminal_safe, usage_fail};
use crate::scan::{redact_path, scan_store, SecretHit};
use crate::store::{
    build_pack, read_store, read_store_unscoped, Store, StoreError, StoreFile, WalkStats,
    MAX_CANONICAL_PACK_BYTES, MAX_PACK_FILES,
};

/// The hub's poll cadence when it does not say otherwise (it always does).
const POLL_INTERVAL_SECS: u64 = 5;

const MAX_JSON_PUSH_BYTES: usize = 4 * 1024 * 1024;
const MAX_STORE_FILES: usize = MAX_PACK_FILES;
const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACK_BYTES: u64 = MAX_CANONICAL_PACK_BYTES;
const PACK_COMMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(330);
/// The hub's byte cap on one vault item, mirrored client-side so an oversized
/// pipe fails before base64 expansion or any request.
const MAX_SECRET_VALUE_BYTES: usize = 256 * 1024;
/// One optional CRLF may be trimmed from piped input.
const MAX_SECRET_STDIN_BYTES: usize = MAX_SECRET_VALUE_BYTES + 2;
const VAULT_EXPORT_FILE: &str = ".sevra-vault.json";
const VAULT_EXPORT_WARNING: &str = "warning: this export includes recoverable vault values; .sevra-vault.json is as sensitive as the credentials themselves. Store it securely and delete it when no longer needed";
const SYNC_BASELINE_FILE: &str = ".sevra-sync.json";
const MAX_SYNC_BASELINE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WITHHELD_PATH_BYTES: usize = 2 * 1024 * 1024;
const PULL_JOURNAL_FILE: &str = ".sevra-pull-journal.json";
const PULL_BACKUP_PREFIX: &str = ".sevra-pull-backup-";
const PULL_LOCK_FILE: &str = ".sevra-pull.lock";
const MAX_PULL_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const ADOPT_JOURNAL_FILE: &str = ".sevra-adopt.json";
const MAX_ADOPT_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncBaseline {
    version: u8,
    brain_id: String,
    brain_slug: String,
    head_seq: u64,
    feed_hash: Option<String>,
    pack_sha256: Option<String>,
    paths: BTreeMap<String, String>,
    #[serde(default)]
    withheld_paths: Vec<String>,
    #[serde(default)]
    kept_home_unlinked: usize,
    #[serde(default)]
    carried_kept_home_unlinked: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PullJournalPhase {
    Preparing,
    Ready,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PullJournalEntry {
    path: String,
    backup: Option<String>,
    old_sha256: Option<String>,
    old_mode: Option<u32>,
    old_readonly: Option<bool>,
    new_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PullJournal {
    version: u8,
    phase: PullJournalPhase,
    backup_dir: String,
    previous_baseline_sha256: String,
    next_baseline_sha256: String,
    created_directories: Vec<String>,
    entries: Vec<PullJournalEntry>,
}

struct PulledSnapshot {
    response: Value,
    brain_id: String,
    brain_slug: String,
    head_seq: u64,
    feed_hash: Option<String>,
    pack_sha256: Option<String>,
    entries: Vec<(String, Vec<u8>)>,
    assets: Vec<crate::assets::AssetDeclaration>,
    withheld_paths: Vec<String>,
    kept_home_unlinked: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultExportFile<'a> {
    version: u8,
    brain: &'a str,
    names: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    values_base64: Option<&'a BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdoptJournal {
    version: u8,
    brain_id: String,
    mappings: BTreeMap<String, String>,
    paths: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct RedactedProvenance {
    name: String,
    kind: String,
}

#[derive(Clone, Debug)]
struct AdoptOccurrence {
    hash: String,
    start: usize,
    end: usize,
    line: usize,
    kind: &'static str,
}

struct AdoptValue {
    bytes: Vec<u8>,
    base_name: String,
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_brain_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn path_rides(scope: Option<&local::LocalScope>, path: &str) -> bool {
    !scope.is_some_and(|value| {
        value.keeps_home(path) || (value.active() && path.rsplit('/').next() == Some("index.md"))
    })
}

fn expected_snapshot_hashes(
    entries: &[(String, Vec<u8>)],
    assets: &[crate::assets::AssetDeclaration],
    scope: Option<&local::LocalScope>,
) -> BTreeMap<String, String> {
    let mut paths = BTreeMap::new();
    for (path, bytes) in entries {
        if path_rides(scope, path) {
            paths.insert(path.clone(), format!("{:x}", Sha256::digest(bytes)));
        }
    }
    for asset in assets {
        if path_rides(scope, &asset.path) {
            paths.insert(asset.path.clone(), asset.sha256.clone());
        }
    }
    paths
}

fn current_store_hashes(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let root_text = root
        .to_str()
        .ok_or_else(|| "store directory is not portable UTF-8".to_string())?;
    let (store, _) = match read_store(root_text, MAX_STORE_BYTES) {
        Ok(value) => value,
        Err(StoreError::OverCap(_)) => {
            return Err("local store exceeds the 512 MB snapshot limit".to_string())
        }
        Err(StoreError::Scope(error)) => return Err(error),
        Err(StoreError::Io(error)) => return Err(format!("could not read local store: {error}")),
    };
    let scope = local::load(root)?;
    let mut hashes = BTreeMap::new();
    for file in &store.files {
        hashes.insert(
            file.path.clone(),
            format!("{:x}", Sha256::digest(file.content.as_bytes())),
        );
    }
    let declarations = match store.assets.as_deref() {
        Some(manifest) => {
            hashes.insert(
                "assets.jsonl".to_string(),
                format!("{:x}", Sha256::digest(manifest.as_bytes())),
            );
            crate::assets::parse_restore_manifest(Some(manifest.as_bytes()))?
        }
        None => Vec::new(),
    };
    hashes.extend(crate::assets::current_declared_asset_hashes(
        root,
        &declarations,
        scope.as_ref(),
    ));
    Ok(hashes)
}

fn validate_sync_baseline(mut baseline: SyncBaseline) -> Result<SyncBaseline, String> {
    if baseline.version != 1 {
        return Err(format!(
            "unsupported {SYNC_BASELINE_FILE} version {}",
            baseline.version
        ));
    }
    if baseline.brain_id.is_empty()
        || baseline.brain_id.len() > 200
        || baseline.brain_id.chars().any(char::is_control)
        || !valid_brain_slug(&baseline.brain_slug)
    {
        return Err(format!(
            "{SYNC_BASELINE_FILE} has an invalid brain identity"
        ));
    }
    if baseline.head_seq == 0 {
        if baseline.feed_hash.is_some() || baseline.pack_sha256.is_some() {
            return Err(format!(
                "{SYNC_BASELINE_FILE} gives an empty brain a snapshot address"
            ));
        }
    } else if !baseline.feed_hash.as_deref().is_some_and(canonical_sha256)
        || !baseline
            .pack_sha256
            .as_deref()
            .is_some_and(canonical_sha256)
    {
        return Err(format!(
            "{SYNC_BASELINE_FILE} has an invalid durable snapshot address"
        ));
    }
    if baseline.paths.len() > MAX_STORE_FILES + 100_000 {
        return Err(format!("{SYNC_BASELINE_FILE} names too many paths"));
    }
    for (path, sha256) in &baseline.paths {
        portable_export_components(path).map_err(|_| {
            format!(
                "{SYNC_BASELINE_FILE} contains an unsafe path: {}",
                terminal_safe(path)
            )
        })?;
        if path == SYNC_BASELINE_FILE || !canonical_sha256(sha256) {
            return Err(format!(
                "{SYNC_BASELINE_FILE} contains an invalid path digest"
            ));
        }
    }
    baseline.withheld_paths =
        validate_hosted_withholding(baseline.withheld_paths, baseline.kept_home_unlinked)?;
    if baseline
        .withheld_paths
        .iter()
        .any(|path| baseline.paths.contains_key(path))
    {
        return Err(format!(
            "{SYNC_BASELINE_FILE} classifies a riding path as withheld"
        ));
    }
    if baseline.carried_kept_home_unlinked > baseline.kept_home_unlinked {
        return Err(format!(
            "{SYNC_BASELINE_FILE} carries more unnamed local-only files than the hosted snapshot"
        ));
    }
    // Canonicalize empty optional strings away before later comparisons.
    baseline.feed_hash = baseline.feed_hash.filter(|value| !value.is_empty());
    baseline.pack_sha256 = baseline.pack_sha256.filter(|value| !value.is_empty());
    Ok(baseline)
}

fn validate_hosted_withholding(
    mut paths: Vec<String>,
    kept_home_unlinked: usize,
) -> Result<Vec<String>, String> {
    if paths.len() > MAX_STORE_FILES || kept_home_unlinked > MAX_STORE_FILES {
        return Err("hub returned too much local-only metadata".to_string());
    }
    let path_bytes: usize = paths.iter().map(String::len).sum();
    if path_bytes > MAX_WITHHELD_PATH_BYTES {
        return Err("hub returned oversized local-only path metadata".to_string());
    }
    for path in &paths {
        validate_portable_core_path(path)
            .map_err(|_| "hub returned an unsafe local-only path".to_string())?;
        if !path.ends_with(".md") {
            return Err("hub returned a non-Markdown local-only path".to_string());
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn load_sync_baseline(root: &Path) -> Result<Option<SyncBaseline>, String> {
    let Some(mut file) = crate::safe_path::open_regular(root, SYNC_BASELINE_FILE)
        .map_err(|error| format!("cannot securely open {SYNC_BASELINE_FILE}: {error}"))?
    else {
        return Ok(None);
    };
    let advertised = file
        .metadata()
        .map_err(|error| format!("cannot inspect {SYNC_BASELINE_FILE}: {error}"))?
        .len();
    if advertised > MAX_SYNC_BASELINE_BYTES {
        return Err(format!("{SYNC_BASELINE_FILE} exceeds its 16 MiB limit"));
    }
    let bytes = read_bounded(&mut file, MAX_SYNC_BASELINE_BYTES)
        .map_err(|error| format!("cannot read {SYNC_BASELINE_FILE}: {error}"))?;
    let baseline: SyncBaseline = serde_json::from_slice(&bytes)
        .map_err(|_| format!("{SYNC_BASELINE_FILE} is not valid baseline JSON"))?;
    validate_sync_baseline(baseline).map(Some)
}

fn baseline_bytes(baseline: &SyncBaseline) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(baseline).expect("baseline serializes");
    bytes.push(b'\n');
    bytes
}

fn write_sync_baseline(root: &Path, baseline: &SyncBaseline) -> Result<(), String> {
    crate::safe_path::atomic_write(
        root,
        SYNC_BASELINE_FILE,
        &baseline_bytes(baseline),
        false,
        0o600,
    )
    .map_err(|error| format!("could not securely update {SYNC_BASELINE_FILE}: {error}"))
}

fn store_from_entries(entries: &[(String, Vec<u8>)]) -> Result<Store, String> {
    let mut store = Store {
        files: Vec::new(),
        assets: None,
    };
    for (path, bytes) in entries {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| format!("hub returned non-UTF-8 store content: {path}"))?;
        if path == "assets.jsonl" {
            store.assets = Some(text.to_string());
        } else {
            store.files.push(StoreFile {
                path: path.clone(),
                content: text.to_string(),
            });
        }
    }
    Ok(store)
}

fn entries_from_store(store: &Store) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = store
        .files
        .iter()
        .map(|file| (file.path.clone(), file.content.as_bytes().to_vec()))
        .collect();
    if let Some(assets) = &store.assets {
        entries.push(("assets.jsonl".to_string(), assets.as_bytes().to_vec()));
    }
    entries
}

fn current_snapshot_address(cfg: &Config, brain: &str) -> (u64, Option<String>) {
    let head = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}", enc(brain)),
            None,
            true,
        ),
        "resolve current brain snapshot",
    );
    let seq = head
        .get("headSeq")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| fail("hub returned no valid feed sequence", None));
    let feed_hash = head
        .get("feedHash")
        .and_then(Value::as_str)
        .map(str::to_string);
    if (seq > 0 && !feed_hash.as_deref().is_some_and(canonical_sha256))
        || (seq == 0 && feed_hash.is_some())
    {
        fail("hub returned an invalid current snapshot address", None);
    }
    (seq, feed_hash)
}

fn snapshot_query(address: Option<(u64, Option<&str>)>, include_vault_names: bool) -> String {
    let mut query = match address {
        Some((seq, feed_hash)) => format!(
            "?format=pack&atSeq={seq}&feedHash={}",
            enc(feed_hash.unwrap_or("none"))
        ),
        None => "?format=pack".to_string(),
    };
    if include_vault_names {
        query.push_str("&includeVaultNames=1");
    }
    query
}

fn request_snapshot(
    cfg: &Config,
    brain: &str,
    exact: Option<(u64, &str)>,
    include_vault_names: bool,
) -> (Value, Option<(u64, Option<String>)>) {
    let requested = exact.map(|(seq, hash)| (seq, Some(hash.to_string())));
    let first = request(
        cfg,
        "GET",
        &format!(
            "/api/hub/brains/{}/export{}",
            enc(brain),
            snapshot_query(
                exact.map(|(seq, hash)| (seq, Some(hash))),
                include_vault_names,
            )
        ),
        None,
        true,
    );
    if exact.is_none()
        && first.status == 400
        && body_code(&first) == Some("snapshot_address_required")
    {
        // Current hubs reject an unpinned pack read. Resolve the signed feed
        // head, then ask for exactly that immutable address. If it advances in
        // between, the hub returns snapshot_not_current instead of silently
        // exporting different bytes; the caller can retry from a fresh head.
        let address = current_snapshot_address(cfg, brain);
        let response = ensure_ok(
            request(
                cfg,
                "GET",
                &format!(
                    "/api/hub/brains/{}/export{}",
                    enc(brain),
                    snapshot_query(Some((address.0, address.1.as_deref())), include_vault_names,)
                ),
                None,
                true,
            ),
            "fetch exact brain snapshot",
        );
        return (response, Some(address));
    }
    (ensure_ok(first, "fetch brain snapshot"), requested)
}

fn fetch_snapshot(cfg: &Config, brain: &str, exact: Option<(u64, &str)>) -> PulledSnapshot {
    let (response, requested) = request_snapshot(cfg, brain, exact, false);
    let brain_id = response
        .get("brain")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .unwrap_or_else(|| fail("hub returned no valid brain identity", None))
        .to_string();
    let brain_slug = response
        .get("slug")
        .and_then(Value::as_str)
        .filter(|value| valid_brain_slug(value))
        .unwrap_or_else(|| fail("hub returned no valid brain slug", None))
        .to_string();
    let head_seq = response
        .get("headSeq")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| fail("hub returned no valid feed sequence", None));
    let feed_hash = response
        .get("feedHash")
        .and_then(Value::as_str)
        .map(str::to_string);
    if head_seq > 0 && !feed_hash.as_deref().is_some_and(canonical_sha256) {
        fail("hub returned an invalid feed hash", None);
    }
    if head_seq == 0 && feed_hash.is_some() {
        fail("hub returned a feed hash for an empty brain", None);
    }
    if let Some((expected_seq, expected_hash)) = requested {
        if head_seq != expected_seq || feed_hash != expected_hash {
            fail(
                "hub returned a snapshot other than the exact requested feed head",
                None,
            );
        }
    }

    let (entries, pack_sha256): (Vec<(String, Vec<u8>)>, Option<String>) =
        if let Some(url) = response.get("url").and_then(Value::as_str) {
            let expected = response
                .get("sha256")
                .and_then(Value::as_str)
                .filter(|sha| canonical_sha256(sha))
                .unwrap_or_else(|| fail("hub returned an invalid pack hash", None));
            let pack = get_presigned(cfg, url, MAX_PACK_BYTES);
            let actual = format!("{:x}", Sha256::digest(&pack));
            if actual != expected {
                fail("downloaded store pack failed SHA-256 verification", None);
            }
            (entries_from_pack(pack), Some(expected.to_string()))
        } else {
            let files = response
                .get("files")
                .and_then(Value::as_array)
                .unwrap_or_else(|| fail("hub returned neither a store pack nor files", None));
            let entries: Vec<(String, Vec<u8>)> = files
                .iter()
                .map(|file| {
                    let path = file
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| fail("refusing malformed file path from hub", None));
                    let content = file
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| fail("refusing malformed file content from hub", None));
                    (path.to_string(), content.as_bytes().to_vec())
                })
                .collect();
            let digest = if entries.is_empty() {
                None
            } else {
                let store = store_from_entries(&entries).unwrap_or_else(|error| fail(&error, None));
                let pack = build_pack(&store)
                    .unwrap_or_else(|error| fail(&format!("invalid hosted store: {error}"), None));
                Some(format!("{:x}", Sha256::digest(pack)))
            };
            (entries, digest)
        };
    if head_seq > 0 && pack_sha256.is_none() {
        fail(
            "hub returned a non-empty feed head without a store pack",
            None,
        );
    }

    let manifest = entries
        .iter()
        .find(|(path, _)| path == "assets.jsonl")
        .map(|(_, bytes)| bytes.as_slice());
    for (path, _) in &entries {
        validate_portable_core_path(path).unwrap_or_else(|error| fail(&error, None));
    }
    let assets =
        crate::assets::parse_restore_manifest(manifest).unwrap_or_else(|error| fail(&error, None));
    let withheld_paths = match response.get("withheldPaths") {
        None => Vec::new(),
        Some(Value::Array(paths)) => paths
            .iter()
            .map(|path| {
                path.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| fail("hub returned malformed local-only metadata", None))
            })
            .collect(),
        Some(_) => fail("hub returned malformed local-only metadata", None),
    };
    let kept_home_unlinked = match response.get("keptHomeUnlinked") {
        None => 0,
        Some(value) => value
            .as_u64()
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or_else(|| fail("hub returned malformed local-only metadata", None)),
    };
    let withheld_paths = validate_hosted_withholding(withheld_paths, kept_home_unlinked)
        .unwrap_or_else(|error| fail(&error, None));
    if withheld_paths
        .iter()
        .any(|withheld| entries.iter().any(|(path, _)| path == withheld))
    {
        fail("hub classified a present snapshot path as local-only", None);
    }
    validate_export_paths(
        entries
            .iter()
            .map(|(path, _)| path.as_str())
            .chain(assets.iter().map(|asset| asset.path.as_str())),
    )
    .unwrap_or_else(|error| fail(&error, None));

    PulledSnapshot {
        response,
        brain_id,
        brain_slug,
        head_seq,
        feed_hash,
        pack_sha256,
        entries,
        assets,
        withheld_paths,
        kept_home_unlinked,
    }
}

pub(crate) fn enc(s: &str) -> String {
    // Percent-encode a path segment for a URL (RFC 3986 unreserved kept).
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

// --- login / logout / whoami -------------------------------------------------

/// Revoke the session this machine is replacing, best-effort. Overwriting the
/// config drops its key_id, and without this the displaced session stays live
/// on the account forever — unrevokable, since nothing on disk points to it
/// any more — quietly eating one of the ten credential slots on every repeat
/// login. Only OUR sessions carry a key_id, so a user-supplied --key is never
/// touched.
fn revoke_displaced_session(hub: &str) {
    let file = config::load_file();
    let (Some(old_key), Some(_)) = (file.key.as_deref(), file.key_id.as_deref()) else {
        return;
    };
    let old_hub = file.hub.clone().unwrap_or_else(|| hub.to_string());
    let safe = (old_hub.starts_with("https://") || old_hub.starts_with("http://127.0.0.1"))
        && !old_key.is_empty()
        && old_key.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if !safe {
        return;
    }
    let cfg = Config {
        hub: old_hub,
        key: Some(old_key.to_string()),
    };
    let _ = crate::hub::try_request(&cfg, "POST", "/api/hub/keys/revoke-self", None, true);
}

pub fn login(flag_hub: Option<String>, key: Option<String>, no_browser: bool) {
    // Env-blind: login PERSISTS a hub, so a one-off SEVRA_HUB_URL must not
    // silently become the stored default. --hub is the explicit path.
    let hub = flag_hub
        .clone()
        .or(config::load_file().hub)
        .unwrap_or_else(|| DEFAULT_HUB.to_string());
    let hub = hub.strip_suffix('/').unwrap_or(&hub).to_string();
    // The apex 308s to www, and redirects strip the authorization header (the
    // safe default), so a valid key probed against the apex reads back as a
    // misleading 401. Normalize the one known apex to the canonical host.
    let hub = if hub == "https://sevrahq.com" {
        note("note: sevrahq.com redirects to www.sevrahq.com; storing the www host");
        DEFAULT_HUB.to_string()
    } else {
        hub
    };
    if flag_hub.is_none() {
        if let Some(env_hub) = config::env_nonempty("SEVRA_HUB_URL") {
            if env_hub.strip_suffix('/').unwrap_or(&env_hub) != hub {
                note(&format!("note: SEVRA_HUB_URL is ignored by login — pass --hub {env_hub} to store that hub"));
            }
        }
    }
    // --key wins and SEVRA_API_KEY stays the scripted fallback.
    if let Some(k) = key.or_else(|| config::env_nonempty("SEVRA_API_KEY")) {
        // A supplied key: verify it against /me, then persist. No key_id is
        // stored — this credential is the user's, so `logout` must never
        // revoke it server-side.
        let key = crate::hub::clean_key(&k);
        let probe_cfg = Config {
            hub: hub.clone(),
            key: Some(key.clone()),
        };
        let probe = request(&probe_cfg, "GET", "/api/hub/me", None, true);
        let email = probe
            .body
            .as_ref()
            .and_then(|b| b.get("email"))
            .and_then(|e| e.as_str())
            .map(String::from);
        if probe.status != 200 || email.is_none() {
            let suffix = if probe.body.is_none() {
                ", non-JSON response"
            } else {
                ""
            };
            fail(
                &format!(
                    "that key did not authenticate against {hub} (HTTP {}{suffix})",
                    probe.status
                ),
                None,
            );
        }
        revoke_displaced_session(&hub);
        if let Err(e) = config::save(&hub, &key, None) {
            fail(&format!("could not write config: {e}"), None);
        }
        let mut data = probe
            .body
            .and_then(|b| b.as_object().cloned())
            .unwrap_or_default();
        data.insert("hub".into(), json!(hub));
        out(
            &format!(
                "logged in to {hub} as {} (config: {})",
                email.unwrap(),
                config::config_path().display()
            ),
            Some(Value::Object(data)),
        );
        return;
    }

    // No key: sign in through the browser. The loopback flow is the automatic
    // path (nothing to read or type); if this machine can't do it — no
    // browser, no local port — fall back to the code flow, which is the one
    // that works over SSH or from another computer.
    //
    // Either way the hub already proved the account binding and returned the
    // email, so we do NOT re-probe /me: a probe blip must never strand a
    // session the hub just minted.
    let signed_in = if no_browser {
        device_flow_key(&hub)
    } else {
        match browser_flow(&hub) {
            Some(signed_in) => signed_in,
            None => {
                note("no browser available here — falling back to a sign-in code");
                device_flow_key(&hub)
            }
        }
    };
    revoke_displaced_session(&hub);
    if let Err(e) = config::save(&hub, &signed_in.key, Some(&signed_in.key_id)) {
        fail(&format!("could not write config: {e}"), None);
    }
    let who = if signed_in.email.is_empty() {
        "your account".to_string()
    } else {
        signed_in.email.clone()
    };
    out(
        &format!(
            "logged in to {hub} as {who} (config: {})",
            config::config_path().display()
        ),
        Some(json!({ "email": signed_in.email, "hub": hub, "keyId": signed_in.key_id })),
    );
}

struct DeviceLogin {
    key: String,
    email: String,
    key_id: String,
}

/// Random URL-safe token from OS entropy (the PKCE verifier is a credential).
fn random_b64url(bytes: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        fail("could not read secure randomness from the OS", None);
    }
    URL_SAFE_NO_PAD.encode(buf)
}

fn challenge_of(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Hand a URL to the platform's browser. Err means we could not even spawn an
/// opener (headless box, no DE, locked-down Windows) — the caller then falls
/// back to the code flow rather than leaving the human staring at nothing.
///
/// SAFETY: callers pass a URL this process BUILT from the validated hub, never
/// one echoed back by the hub. Windows launches Explorer directly rather than
/// routing the URL through `cmd /C start`, so shell metacharacters are never
/// interpreted. `open`/`xdg-open` receive a parsed HTTPS URL that cannot begin
/// with an option or switch schemes.
fn open_browser(url: &str) -> Result<(), String> {
    let parsed =
        url::Url::parse(url).map_err(|_| "refusing to open an invalid browser URL".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("refusing to open a non-https or unsafe URL".into());
    }
    let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "windows") {
        ("explorer.exe", vec![url])
    } else {
        ("xdg-open", vec![url])
    };
    match Command::new(program)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

const LOOPBACK_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Signed in</title>\
<style>body{font-family:ui-sans-serif,system-ui,sans-serif;background:#f4f3ee;color:#020617;\
display:grid;place-items:center;height:100vh;margin:0}div{text-align:center}\
p{color:#64748b;font-size:14px}</style>\
<div><h2>You're signed in.</h2><p>Return to your terminal. You can close this tab.</p></div>";

/// The automatic sign-in: bind a loopback port, send the human to the hub to
/// approve, and collect the session when the browser is handed back to us.
/// Returns None when this machine can't do it (no listener, no browser), so
/// the caller can fall back to the code flow.
fn browser_flow(hub: &str) -> Option<DeviceLogin> {
    use std::io::Write;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    let cfg = Config {
        hub: hub.to_string(),
        key: None,
    };
    let verifier = random_b64url(32);
    let body = json!({
        "challenge": challenge_of(&verifier),
        "port": port,
        "client": machine_label(),
    });
    let started = ensure_ok(
        request(&cfg, "POST", "/api/hub/auth/cli/start", Some(&body), false),
        "starting sign-in",
    );
    let request_id = str_field(&started, "requestId").to_string();
    // Build the URL OURSELVES from the already-validated hub plus a strictly
    // checked id. The hub's own `approveUrl` is never opened: it would be
    // remote text reaching a process spawner (on Windows, cmd's parser), which
    // is a command-injection surface no amount of escaping makes comfortable.
    if request_id.is_empty() || !request_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let approve_url = format!("{hub}/device?request={request_id}");
    let expires_in = started
        .get("expiresIn")
        .and_then(|v| v.as_u64())
        .unwrap_or(600)
        .clamp(60, 1800);

    // Arm the listener BEFORE opening the browser: if we cannot, we must fall
    // back without having already sent the human to an approval page.
    if listener.set_nonblocking(true).is_err() {
        return None;
    }
    if open_browser(&approve_url).is_err() {
        return None; // headless: the caller falls back to the code flow
    }
    if json_mode() {
        println!(
            "{}",
            json!({
                "status": "awaiting_approval",
                "method": "browser",
                "approveUrl": approve_url,
                "expiresIn": expires_in,
            })
        );
    } else {
        println!("Approve this sign-in in your browser:");
        println!("  {}", terminal_safe(&approve_url));
        println!("Waiting…");
    }

    // Wait for the browser to hand us the authorization code. Non-blocking
    // accept so the wait is bounded by the approval window, and a read timeout
    // on each connection so a socket that never speaks cannot park us forever
    // (browsers speculatively preconnect to loopback and send nothing).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    let mut auth_code: Option<String> = None;
    while std::time::Instant::now() < deadline && auth_code.is_none() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).ok();
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                // Read until we have the whole request line; a single read can
                // split it ("GET /c") and drop the callback on the floor.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(2).any(|w| w == b"\r\n") && buf.len() < 8192 {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let line = head.lines().next().unwrap_or("");
                // Only a callback CARRYING THE CODE counts. A bare probe (or a
                // local process poking the port) gets a 404 and we keep
                // waiting for the real redirect.
                let code = line
                    .strip_prefix("GET /cb?")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|q| {
                        q.split('&')
                            .find_map(|p| p.strip_prefix("code="))
                            .map(str::to_string)
                    })
                    .filter(|c| {
                        !c.is_empty()
                            && c.chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                    });
                if let Some(code) = code {
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            LOOPBACK_PAGE.len(),
                            LOOPBACK_PAGE
                        )
                        .as_bytes(),
                    );
                    auth_code = Some(code);
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    );
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(_) => break,
        }
    }
    let Some(auth_code) = auth_code else {
        fail(
            "the browser never came back — approve in the browser, or run `sevra login --no-browser` to use a code instead",
            None,
        )
    };

    // Two proofs, both required: the verifier (we started this) and the code
    // (the browser handed it to US, on this machine).
    let mut wait_secs = 1;
    for attempt in 0..8 {
        let resp = match crate::hub::try_request(
            &cfg,
            "POST",
            "/api/hub/auth/cli/exchange",
            Some(&json!({
                "requestId": request_id,
                "verifier": verifier,
                "code": auth_code,
            })),
            false,
        ) {
            Ok(resp) => resp,
            Err(t) if attempt == 7 => fail(
                &format!("could not reach the hub to finish sign-in: {t}"),
                None,
            ),
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_secs(wait_secs));
                wait_secs = (wait_secs * 2).min(8);
                continue;
            }
        };
        let body = resp.body.clone().unwrap_or(Value::Null);
        match (resp.status, str_field(&body, "status")) {
            (200, "approved") => {
                let key = crate::hub::clean_key(str_field(&body, "key"));
                if key.is_empty() {
                    fail(
                        "the hub approved the sign-in but sent no key — try again",
                        None,
                    );
                }
                return Some(DeviceLogin {
                    key,
                    email: str_field(&body, "email").to_string(),
                    key_id: str_field(&body, "keyId").to_string(),
                });
            }
            (200, "pending") => std::thread::sleep(std::time::Duration::from_secs(1)),
            (200, "denied") => fail("the sign-in was denied in the browser", None),
            (200, "failed") => fail(
                &format!(
                    "the hub could not finish sign-in: {}",
                    str_field(&body, "error")
                ),
                None,
            ),
            // Throttling and hub trouble are transient, not "unrecognized" —
            // back off and keep trying rather than killing a live sign-in.
            (429, _) | (500..=599, _) => {
                std::thread::sleep(std::time::Duration::from_secs(wait_secs));
                wait_secs = (wait_secs * 2).min(8);
            }
            _ => fail(
                "the hub no longer recognizes this sign-in — run `sevra login` again",
                None,
            ),
        }
    }
    fail("sign-in did not complete — run `sevra login` again", None);
}

/// The approve-in-browser sign-in (`sevra login` with no key): start a device
/// authorization, show the human the code + URL, poll until the hub hands
/// back a fresh account key. The device code never leaves this process; the
/// human types nothing but a click.
///
/// Agent contract for `--json`: the FIRST stdout line is a compact JSON
/// `awaiting_approval` event (relay its URL + code); the FINAL stdout value is
/// the pretty-printed login object. Read line 1 as an event, then parse the
/// remainder as one object.
fn device_flow_key(hub: &str) -> DeviceLogin {
    let cfg = Config {
        hub: hub.to_string(),
        key: None,
    };
    let body = match machine_label() {
        Some(name) => json!({ "client": name }),
        None => json!({}),
    };
    let started = ensure_ok(
        request(&cfg, "POST", "/api/hub/auth/device", Some(&body), false),
        "starting sign-in",
    );
    let device_code = str_field(&started, "deviceCode").to_string();
    let user_code = str_field(&started, "userCode").to_string();
    if device_code.is_empty() || user_code.is_empty() {
        fail(
            "the hub's sign-in answer was missing the codes — is this a Sevra hub? (`sevra login --key …` still works)",
            None,
        );
    }
    let verify_at = {
        let complete = str_field(&started, "verificationUriComplete");
        if complete.is_empty() {
            format!("{hub}/device")
        } else {
            complete.to_string()
        }
    };
    // Clamp the hub-supplied timings: a remote value must never make the CLI
    // busy-loop (interval 0), sleep for a day (interval huge), overflow the
    // deadline (expiresIn near u64::MAX), or give up before the first poll
    // (expiresIn <= interval).
    let interval = started
        .get("interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(POLL_INTERVAL_SECS)
        .clamp(1, 60);
    let expires_in = started
        .get("expiresIn")
        .and_then(|v| v.as_u64())
        .unwrap_or(900)
        .clamp(interval + 30, 1800);

    if json_mode() {
        println!(
            "{}",
            json!({
                "status": "awaiting_approval",
                "userCode": user_code,
                "verificationUri": str_field(&started, "verificationUri"),
                "verificationUriComplete": verify_at,
                "expiresIn": expires_in,
                "interval": interval,
            })
        );
    } else {
        println!(
            "First, confirm this code in your browser: {}",
            terminal_safe(&user_code)
        );
        println!("Open: {}", terminal_safe(&verify_at));
        println!("Waiting for approval…");
    }

    // Backoff grows the gap on throttle or trouble, capped, and never below the
    // hub's interval; the whole loop is bounded by the deadline.
    // clamp() ASSERTS min <= max, so the floor must never exceed the ceiling:
    // interval is allowed up to 60, and a hub sending 45 would otherwise panic
    // the process on the first 429 or 5xx — the clamp block exists precisely
    // to survive hostile timings, so it must not be the thing that crashes.
    let ceiling = interval.max(30);
    let backoff = move |w: u64| w.saturating_mul(2).clamp(interval, ceiling);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    let mut wait = interval;
    let mut last_trouble: Option<String> = None;
    loop {
        if std::time::Instant::now() >= deadline {
            match last_trouble {
                Some(t) => fail(
                    &format!("sign-in did not complete — the hub had trouble ({t}). Run `sevra login` again."),
                    None,
                ),
                None => fail("the approval window closed — run `sevra login` again", None),
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(wait));
        // try_request, not request: a transport blip mid-wait must be retried,
        // not fatal.
        let resp = match crate::hub::try_request(
            &cfg,
            "POST",
            "/api/hub/auth/device/token",
            Some(&json!({ "deviceCode": device_code })),
            false,
        ) {
            Ok(resp) => resp,
            Err(t) => {
                last_trouble = Some(t);
                wait = backoff(wait);
                continue;
            }
        };
        match resp.status {
            200 => {
                let body = resp.body.unwrap_or(Value::Null);
                match str_field(&body, "status") {
                    "pending" => {
                        wait = interval;
                        last_trouble = None;
                    }
                    "approved" => {
                        let key = crate::hub::clean_key(str_field(&body, "key"));
                        if key.is_empty() {
                            fail(
                                "the hub approved the sign-in but sent no key — try again",
                                None,
                            );
                        }
                        return DeviceLogin {
                            key,
                            email: str_field(&body, "email").to_string(),
                            key_id: str_field(&body, "keyId").to_string(),
                        };
                    }
                    "denied" => fail("the sign-in was denied in the dashboard", None),
                    "failed" => {
                        // The hub's own message only — never echo its whole
                        // body to stdout on a credential path.
                        let msg = str_field(&body, "error");
                        fail(&format!("the hub could not finish sign-in: {msg}"), None)
                    }
                    other => fail(
                        &format!("unexpected sign-in state from the hub: {other:?}"),
                        None,
                    ),
                }
            }
            // Throttled: grow the gap. Repeated 429s back off further, so the
            // client self-adjusts to whatever pace the hub wants.
            429 => wait = backoff(wait),
            400 => {
                let code = resp
                    .body
                    .as_ref()
                    .and_then(|b| b.get("code"))
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                if code == "expired" {
                    fail("the code expired — run `sevra login` again", None);
                }
                fail(
                    "the hub no longer recognizes this sign-in — run `sevra login` again",
                    None,
                );
            }
            // A transient hub error must not kill the wait: back off and keep
            // trying until the deadline (not a fixed retry count).
            s if s >= 500 => {
                last_trouble = Some(format!("HTTP {s}"));
                wait = backoff(wait);
            }
            s => fail(
                &format!("unexpected hub answer during sign-in (HTTP {s})"),
                None,
            ),
        }
    }
}

/// A cosmetic label for the approval page + the minted key's name. `hostname`
/// exists on every target OS; anything odd just means no label.
fn machine_label() -> Option<String> {
    let out = Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub fn logout() {
    // Revoke a browser-minted key server-side first (best-effort): device
    // sign-ins each mint a fresh key, so without this they pile up unrevoked
    // against the account cap. Only keys WE minted carry a key_id; a
    // user-supplied `--key` has none and is left alone (they may use it
    // elsewhere). A network failure here must never block the local logout.
    let file = config::load_file();
    if let (Some(key), Some(_id)) = (file.key.as_deref(), file.key_id.as_deref()) {
        let hub = file
            .hub
            .clone()
            .unwrap_or_else(|| config::DEFAULT_HUB.to_string());
        // Pre-check what the hub client would otherwise ABORT the process over
        // (a non-HTTPS stored hub, a key with stray bytes). try_request routes
        // those through fail(), which would exit before we ever remove the
        // credential file — the exact situation where removing it matters most.
        let safe_hub = hub.starts_with("https://") || hub.starts_with("http://127.0.0.1");
        let safe_key = !key.is_empty() && key.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if safe_hub && safe_key {
            let cfg = Config {
                hub,
                key: Some(key.to_string()),
            };
            // auth:true sends the very key we are revoking as the bearer — the
            // hub revokes exactly the presented credential.
            let confirmed = matches!(
                crate::hub::try_request(&cfg, "POST", "/api/hub/keys/revoke-self", None, true),
                Ok(r) if r.status == 200
                    && r.body.as_ref().and_then(|b| b.get("revoked")).and_then(|v| v.as_bool()) == Some(true)
            );
            // Never silently claim a clean logout: the key is about to leave
            // this machine, so the human needs to know if it is still live.
            if !confirmed {
                note("could not confirm the sign-in was revoked on the hub — revoke it under Account → Sign-ins");
            }
        } else {
            note("skipped the server-side revoke (stored hub or key looks malformed) — revoke under Account → Sign-ins");
        }
    }

    // Honest about what happened: a credential file that EXISTS but cannot be
    // removed must be a loud failure (the key would silently survive on disk),
    // and a no-op logout must not claim it removed anything.
    match config::remove() {
        Ok(true) => out(
            "logged out (removed ~/.sevra/config.json)",
            Some(json!({ "ok": true, "removed": true })),
        ),
        Ok(false) => out(
            "logged out (no stored credential to remove)",
            Some(json!({ "ok": true, "removed": false })),
        ),
        Err(e) => fail(
            &format!(
                "could not remove {} — the stored key is STILL on disk: {e}",
                config::config_path().display()
            ),
            None,
        ),
    }
}

pub fn whoami(cfg: &Config) {
    let me = ensure_ok(request(cfg, "GET", "/api/hub/me", None, true), "whoami");
    out(
        &format!(
            "{} ({}) @ {}",
            str_field(&me, "email"),
            str_field(&me, "userId"),
            cfg.hub
        ),
        Some(me),
    );
}

// --- brains ------------------------------------------------------------------

pub fn brains(cfg: &Config) {
    let r = ensure_ok(
        request(cfg, "GET", "/api/hub/brains", None, true),
        "list brains",
    );
    let list = r
        .get("brains")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    if json_mode() {
        out("", Some(json!({ "brains": list })));
        return;
    }
    if list.is_empty() {
        out("no brains yet — `sevra create <slug>`", None);
        return;
    }
    for b in list {
        out_layout(
            &format!(
                "{}\t{}\t{}\t{}",
                terminal_safe(str_field(&b, "slug")),
                terminal_safe(str_field(&b, "id")),
                terminal_safe(str_field(&b, "visibility")),
                terminal_safe(str_field(&b, "name"))
            ),
            None,
        );
    }
}

pub fn create(cfg: &Config, slug: &str, name: Option<String>, scope: Option<String>, public: bool) {
    let body = json!({
        "slug": slug,
        "name": name,
        "scope": scope,
        "visibility": if public { "public" } else { "private" },
    });
    let b = ensure_ok(
        request(cfg, "POST", "/api/hub/brains", Some(&body), true),
        "create brain",
    );
    out(
        &format!(
            "created brain {} ({}, {})",
            str_field(&b, "slug"),
            str_field(&b, "id"),
            str_field(&b, "visibility")
        ),
        Some(b),
    );
}

/// Interactive confirmation for `delete`: show what dies, require the slug
/// typed back. Scripted callers (no TTY, or --json) must pass --confirm.
fn prompt_delete_confirmation(cfg: &Config, brain: &str) -> String {
    use std::io::IsTerminal;
    if json_mode() || !std::io::stdin().is_terminal() {
        fail(
            "deleting a brain is permanent and needs confirmation — rerun with --confirm <slug> (the brain's exact slug; `sevra brains` lists them)",
            None,
        );
    }
    // Show what will be deleted — and learn the slug the hub will demand,
    // so an id-referenced delete still confirms against the right word.
    let r = ensure_ok(request(cfg, "GET", "/api/hub/brains", None, true), "delete");
    let list = r
        .get("brains")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    let Some(b) = list
        .iter()
        .find(|b| str_field(b, "slug") == brain || str_field(b, "id") == brain)
    else {
        fail(
            &format!("no brain '{brain}' in your account — `sevra brains` lists yours"),
            None,
        )
    };
    let slug = str_field(b, "slug").to_string();
    let name = str_field(b, "name");
    let label = if name.is_empty() || name == slug {
        format!("'{slug}'")
    } else {
        format!("'{slug}' ({name})")
    };
    eprintln!(
        "This permanently deletes {} from the hub — every hosted file, its index, published pages, and grants. There is no undo.",
        terminal_safe(&label)
    );
    eprint!("type the brain's slug to confirm: ");
    let mut typed = String::new();
    if std::io::stdin().read_line(&mut typed).is_err() {
        fail(
            "could not read the confirmation — nothing was deleted",
            None,
        );
    }
    let typed = typed.trim();
    if typed != slug {
        fail(
            &format!("confirmation did not match the slug '{slug}' — nothing was deleted"),
            None,
        );
    }
    typed.to_string()
}

pub fn delete(cfg: &Config, brain: &str, confirm: Option<String>) {
    let confirm = confirm.unwrap_or_else(|| prompt_delete_confirmation(cfg, brain));
    let resp = request(
        cfg,
        "DELETE",
        &format!("/api/hub/brains/{}", enc(brain)),
        Some(&json!({ "confirm": confirm })),
        true,
    );
    // The hub's own guard: a missing or mismatched confirm answers 400
    // confirm_required. Map it to the action that unblocks.
    if resp.status == 400 && body_code(&resp) == Some("confirm_required") {
        let server = resp
            .body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("the hub requires the brain's slug to confirm")
            .to_string();
        fail(
            &format!(
                "delete refused (HTTP 400): {server}\nconfirm with the brain's exact slug: sevra delete {brain} --confirm <slug> (`sevra brains` lists slugs)"
            ),
            resp.body,
        );
    }
    let r = ensure_ok(resp, "delete");
    let objects = r.get("r2Objects").and_then(|v| v.as_i64()).unwrap_or(0);
    out(
        &format!("deleted {brain} permanently ({objects} hosted object(s) removed)"),
        Some(r),
    );
}

// --- push --------------------------------------------------------------------

/// Bytes for humans, in the binary units the hub's limits are defined in.
pub(crate) fn human_size(bytes: u64) -> String {
    const K: f64 = 1024.0;
    let b = bytes as f64;
    if b >= K * K * K {
        format!("{:.1} GiB", b / (K * K * K))
    } else if b >= K * K {
        format!("{:.1} MiB", b / (K * K))
    } else if b >= K {
        format!("{:.1} KiB", b / K)
    } else {
        format!("{bytes} B")
    }
}

/// 100000 → "100,000" — counts read at a glance in refusal messages.
fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    grouped
}

/// Refuse, locally, a push the hub's snapshot limits would reject anyway —
/// before a single byte is uploaded — naming the limit, the actual numbers,
/// and the largest files so the operator knows what to trim.
fn fail_snapshot_limit(problem: &str, largest: &[(String, u64)], data: Value) -> ! {
    let mut msg = format!("{problem}\nlargest files:");
    for (path, bytes) in largest {
        msg.push_str(&format!("\n  {:>9}  {path}", human_size(*bytes)));
    }
    msg.push_str(
        "\ntrim what should not ship (sources/ usually holds the bulk); for a deliberately large store, split it across brains and push each part separately",
    );
    let mut data = data;
    if let Some(obj) = data.as_object_mut() {
        obj.insert(
            "largestFiles".into(),
            json!(largest
                .iter()
                .map(|(path, bytes)| json!({ "path": path, "bytes": bytes }))
                .collect::<Vec<_>>()),
        );
    }
    fail(&msg, Some(data));
}

/// How many secret hits a refusal shows before eliding.
const SECRET_HITS_SHOWN: usize = 20;
const EXISTING_BYTES_REMEDIATION: &str = "Already-pushed bytes persist in retained packs; a kept-home asset remains declared, so its blob is not swept; retention-locked backups persist for about 31 days. Rotate at the issuer immediately. Byte erasure requires `sevra delete`, completion of the sweep and backup-retention window, then a fresh push.";

/// The hit list block shared by push's refusal and `secrets scan`: each hit
/// as `path — kind`, never a matched value (paths that themselves match are
/// already redacted by the scanner), capped at `SECRET_HITS_SHOWN`.
fn secret_hits_block(hits: &[SecretHit]) -> String {
    let mut msg = String::new();
    for hit in hits.iter().take(SECRET_HITS_SHOWN) {
        let place = if hit.in_path {
            " (in the file's name)"
        } else {
            ""
        };
        msg.push_str(&format!("\n  {} — {}{place}", hit.path, hit.kind));
    }
    if hits.len() > SECRET_HITS_SHOWN {
        msg.push_str(&format!(
            "\n  … and {} more",
            hits.len() - SECRET_HITS_SHOWN
        ));
    }
    msg
}

/// The machine half of the same refusal — one shape for push and scan.
fn secret_hits_data(hits: &[SecretHit]) -> Value {
    json!({
        "secretHits": hits
            .iter()
            .take(SECRET_HITS_SHOWN)
            .map(|h| json!({ "path": h.path, "kind": h.kind, "inPath": h.in_path }))
            .collect::<Vec<_>>(),
        "total": hits.len(),
    })
}

/// The push secret-scan refusal, naming the exits in safety order: adopt a
/// content literal, keep a whole secret-bearing file home, edit deliberately,
/// or make the explicit unsafe override.
fn fail_secret_hits(
    hits: &[SecretHit],
    dir: &str,
    asset_scan: Option<&crate::assets::AssetSecretScanReport>,
) -> ! {
    let mut msg = format!(
        "push refused: {} match(es) for known secret formats in the store (matched values are never shown):",
        hits.len()
    );
    msg.push_str(&secret_hits_block(hits));
    msg.push_str(&format!(
        "\nrotate anything that ever lived here; keep live secrets in a password manager and references to them in the brain.\n{EXISTING_BYTES_REMEDIATION}\nways out, in order: `sevra secrets adopt {dir}` (move markdown literals into the brain vault) · `sevra secrets quarantine {dir}` (only when the whole file is secret or an asset) · edit deliberately · `--allow-secrets` (push verbatim)"
    ));
    let mut data = secret_hits_data(hits);
    if let (Some(scan), Some(object)) = (asset_scan, data.as_object_mut()) {
        object.insert("assetSecretScan".into(), scan.to_json());
    }
    fail(&msg, Some(data));
}

fn body_code(r: &HubResponse) -> Option<&str> {
    r.body
        .as_ref()
        .and_then(|b| b.get("code"))
        .and_then(|c| c.as_str())
}

/// `ensure_ok` for the push verbs, with the shrink guard mapped: without
/// --force, a 409 `shrink_refused` (the hub protecting a brain from a smaller
/// replacement) prints the hub's message verbatim plus the one hint that
/// unblocks an intended replacement — and, when the walk kept files home,
/// the line that explains part of the difference.
fn ensure_push_ok(r: HubResponse, what: &str, force: bool, kept_home: usize) -> Value {
    if !force && r.status == 409 && body_code(&r) == Some("shrink_refused") {
        let server = r
            .body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("the hub refused to shrink the brain")
            .to_string();
        let mut msg = format!(
            "{what} failed (HTTP 409): {server}\nretry with --force if the replacement is intended"
        );
        if kept_home > 0 {
            msg.push_str(&format!(
                "\n({kept_home} document(s) are kept home by .sevralocal and not part of this push)"
            ));
        }
        fail(&msg, r.body);
    }
    ensure_ok(r, what)
}

/// Commit an uploaded pack. A 507 `hub_scratch_exhausted` means the pack IS
/// uploaded and only the hub's unpack scratch is busy — retry the commit
/// after a pause, never the upload.
fn commit_pack(cfg: &Config, brain: &str, commit: &Value, force: bool, kept_home: usize) -> Value {
    let mut attempt: u64 = 0;
    loop {
        let resp = request_with_timeout(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/packs/commit", enc(brain)),
            Some(commit),
            true,
            PACK_COMMIT_TIMEOUT,
        );
        if resp.status == 507 && body_code(&resp) == Some("hub_scratch_exhausted") && attempt < 2 {
            attempt += 1;
            let pause = 5 * attempt;
            note(&format!(
                "the hub's unpack scratch is busy — the pack is already uploaded; retrying the commit in {pause}s ({attempt}/2)"
            ));
            std::thread::sleep(std::time::Duration::from_secs(pause));
            continue;
        }
        return ensure_push_ok(resp, "commit pack", force, kept_home);
    }
}

/// The shared store read for push, scan, and quarantine — every store error
/// maps to the same refusal push uses. `scoped` reads what a push would
/// carry (`.sevralocal` honored); unscoped is quarantine's full view.
fn read_store_checked(dir: &str, scoped: bool) -> (Store, WalkStats) {
    let result = if scoped {
        read_store(dir, MAX_STORE_BYTES)
    } else {
        read_store_unscoped(dir, MAX_STORE_BYTES)
    };
    match result {
        Ok(pair) => pair,
        Err(StoreError::OverCap(stats)) => fail_snapshot_limit(
            &format!(
                "store is {} uncompressed across {} files — the hub caps one snapshot at {} uncompressed",
                human_size(stats.bytes),
                commas(stats.files as u64),
                human_size(MAX_STORE_BYTES)
            ),
            &stats.largest,
            json!({ "limitBytes": MAX_STORE_BYTES, "storeBytes": stats.bytes, "files": stats.files }),
        ),
        Err(StoreError::Scope(msg)) => fail(&msg, None),
        Err(StoreError::Io(e)) => fail(&format!("could not read {dir}: {e}"), None),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct WithheldPushMetadata {
    paths: Vec<String>,
    unlinked: usize,
}

/// Declare only kept-home names the hub already sees as link targets in the
/// riding content. Every other kept-home filename remains local; only its
/// contribution to `unlinked` crosses the boundary.
fn withheld_push_metadata(
    dir: &str,
    held_root: &crate::safe_path::SafeDir,
    store: &Store,
    stats: &WalkStats,
    scope: Option<&local::LocalScope>,
    baseline: Option<&SyncBaseline>,
) -> WithheldPushMetadata {
    let kept_total = stats.kept_home + stats.catalogs_kept;
    let active_scope = scope.filter(|scope| scope.active());
    let trusted_paths: BTreeSet<&str> = baseline
        .into_iter()
        .flat_map(|baseline| baseline.withheld_paths.iter().map(String::as_str))
        .collect();
    let carried_unlinked = baseline
        .map(|baseline| baseline.carried_kept_home_unlinked)
        .unwrap_or(0);
    if active_scope.is_none() && trusted_paths.is_empty() && carried_unlinked == 0 {
        return WithheldPushMetadata {
            paths: Vec::new(),
            unlinked: 0,
        };
    }
    if kept_total == 0 && trusted_paths.is_empty() {
        return WithheldPushMetadata {
            paths: Vec::new(),
            unlinked: carried_unlinked,
        };
    }
    // No possible wiki-link token means no name needs parsing or disclosure.
    // This fast path also keeps an unlinked local-only file from turning a
    // routine push into a dependency on a second process.
    if !store.files.iter().any(|file| file.content.contains("[[")) {
        return WithheldPushMetadata {
            paths: Vec::new(),
            unlinked: kept_total.saturating_add(carried_unlinked),
        };
    }

    // dbmd is the format authority for fence-aware wiki-link recognition and
    // path normalization. A push with possible linked omissions refuses if it
    // cannot compute the exact declaration; guessing would relabel true rot.
    let emit = run_dbmd_emit_for(dir, "push withheld accounting");
    let files = emit
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            fail(
                "push withheld accounting: `dbmd emit --json` returned no files array",
                None,
            )
        });
    let existing: BTreeSet<&str> = files
        .iter()
        .filter_map(|file| file.get("path").and_then(Value::as_str))
        .collect();
    let riding: BTreeSet<&str> = store.files.iter().map(|file| file.path.as_str()).collect();
    let mut paths = BTreeSet::new();
    let mut locally_withheld = BTreeSet::new();
    for file in &files {
        let Some(src) = file.get("path").and_then(Value::as_str) else {
            continue;
        };
        if !riding.contains(src) {
            continue;
        }
        for link in file
            .get("links")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(target) = link.as_str() else {
                continue;
            };
            if paths.contains(target) || riding.contains(target) {
                continue;
            }
            // Use the exact same keep-home predicate as the snapshot walk.
            // An active .sevralocal keeps both explicitly matched files and
            // derived index.md catalogs off the wire; linked catalogs must be
            // declared withheld too or the hub misclassifies them as broken.
            // dbmd emit deliberately omits generated catalogs from its file
            // inventory, so prove those candidates exist through the already
            // held, no-follow store capability before relabeling the edge.
            let locally_exists = existing.contains(target)
                || (target.rsplit('/').next() == Some("index.md")
                    && held_root.open_relative(target).unwrap_or_else(|error| {
                        fail(
                            &format!(
                                "push withheld accounting could not securely verify a linked derived catalog: {error}"
                            ),
                            None,
                        )
                    }).is_some());
            let local_omission = active_scope.is_some_and(|scope| !path_rides(Some(scope), target))
                && locally_exists;
            if local_omission {
                locally_withheld.insert(target.to_string());
                paths.insert(target.to_string());
            } else if trusted_paths.contains(target) && !existing.contains(target) {
                // A clone cannot possess the omitted body. The immutable
                // snapshot baseline is the proof that this exact missing
                // target was intentionally withheld at the feed head it
                // cloned. Reuse that proof only while riding content still
                // links to the same absent path; every new missing target
                // remains genuinely broken.
                paths.insert(target.to_string());
            }
        }
    }
    let paths: Vec<String> = paths.into_iter().collect();
    WithheldPushMetadata {
        unlinked: kept_total
            .saturating_sub(locally_withheld.len())
            .saturating_add(carried_unlinked),
        paths,
    }
}

pub fn push(
    cfg: &Config,
    dir: &str,
    brain: &str,
    force: bool,
    allow_secrets: bool,
    skip_assets: bool,
) {
    if !Path::new(dir).exists() {
        fail(&format!("store directory not found: {dir}"), None);
    }
    let root = std::fs::canonicalize(dir)
        .unwrap_or_else(|error| fail(&format!("could not resolve store directory: {error}"), None));
    let held_root = crate::safe_path::SafeDir::open(&root).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely hold store directory: {error}"),
            None,
        )
    });
    let _pull_lock = held_root
        .lock_relative(PULL_LOCK_FILE)
        .unwrap_or_else(|error| fail(&format!("cannot lock store sync state: {error}"), None));
    if recover_pull_transaction(&held_root).unwrap_or_else(|error| fail(&error, None)) {
        note("recovered an interrupted pull before reading the store");
    }
    let prior_baseline = load_sync_baseline(&root).unwrap_or_else(|error| fail(&error, None));
    let (store, stats) = read_store_checked(dir, true);
    if store.files.is_empty() {
        let kept = stats.kept_home + stats.catalogs_kept;
        if kept > 0 {
            fail(
                &format!(
                    "no .md files to push under {dir} — all {kept} file(s) are kept home (.sevralocal)"
                ),
                Some(
                    json!({ "keptHome": stats.kept_home, "catalogsKeptHome": stats.catalogs_kept }),
                ),
            );
        }
        fail(&format!("no .md files under {dir}"), None);
    }
    if stats.files > MAX_STORE_FILES {
        fail_snapshot_limit(
            &format!(
                "store has {} files — the hub caps one snapshot at {} files",
                commas(stats.files as u64),
                commas(MAX_STORE_FILES as u64)
            ),
            &stats.largest,
            json!({ "limitFiles": MAX_STORE_FILES, "files": stats.files }),
        );
    }
    // Load once for both the asset secret gate and the eventual byte sync.
    // The markdown walk already validated this file; repeating the secure
    // load binds the following asset decisions to one explicit scope value.
    let scope = local::load(Path::new(dir)).unwrap_or_else(|msg| fail(&msg, None));
    let withheld = withheld_push_metadata(
        dir,
        &held_root,
        &store,
        &stats,
        scope.as_ref(),
        prior_baseline.as_ref(),
    );
    let withheld_path_bytes: usize = withheld.paths.iter().map(|path| path.len()).sum();
    if withheld.paths.len() > MAX_STORE_FILES || withheld_path_bytes > MAX_WITHHELD_PATH_BYTES {
        fail(
            &format!(
                "withheld declaration is too large ({} paths / {} UTF-8 bytes); reduce linked .sevralocal scope before pushing",
                withheld.paths.len(),
                withheld_path_bytes
            ),
            Some(json!({
                "code": "withheld_declaration_too_large",
                "paths": withheld.paths.len(),
                "pathBytes": withheld_path_bytes,
            })),
        );
    }
    // The last gate before bytes leave the machine: refuse secret-shaped
    // content and file names unless the operator explicitly overrides. Asset
    // bytes are checked against their exact manifest length and digest before
    // the first hub request; --skip-assets correctly skips bytes that will not
    // upload during this push.
    let mut asset_secret_scan = None;
    if !allow_secrets {
        let mut hits = scan_store(&store);
        if !skip_assets {
            let mut scan = crate::assets::scan_declared_asset_secrets(
                dir,
                store.assets.as_deref(),
                scope.as_ref(),
                false,
            );
            if let Some(message) = scan.coverage_note() {
                note(&message);
            }
            hits.append(&mut scan.hits);
            asset_secret_scan = Some(scan);
        }
        if !hits.is_empty() {
            fail_secret_hits(&hits, dir, asset_secret_scan.as_ref());
        }
    }
    if let Some(baseline) = &prior_baseline {
        let remote = ensure_ok(
            request(
                cfg,
                "GET",
                &format!("/api/hub/brains/{}", enc(brain)),
                None,
                true,
            ),
            "check clone identity",
        );
        let remote_id = remote
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("hub returned no valid brain identity", None));
        if remote_id != baseline.brain_id {
            fail(
                &format!(
                    "this clone belongs to brain {}; refusing to push it to a different brain",
                    terminal_safe(&baseline.brain_slug)
                ),
                Some(json!({
                    "code": "brain_identity_mismatch",
                    "baselineBrain": baseline.brain_id,
                    "requestedBrain": remote_id,
                })),
            );
        }
    }
    let mut payload = serde_json::to_value(&store).unwrap();
    payload["withheld_paths"] = json!(withheld.paths);
    payload["kept_home_unlinked"] = json!(withheld.unlinked);
    if force {
        payload["allow_shrink"] = json!(true);
    } else if let Some(baseline) = &prior_baseline {
        payload["expected_head_seq"] = json!(baseline.head_seq);
    }
    let file_count = store.files.len();
    // Everything the walk kept home — the honest count when the hub's shrink
    // guard asks where the missing documents went.
    let kept_total = stats.kept_home + stats.catalogs_kept;
    let payload_bytes = payload.to_string().len();
    let r = if payload_bytes <= MAX_JSON_PUSH_BYTES {
        ensure_push_ok(
            request(
                cfg,
                "POST",
                &format!("/api/hub/brains/{}/push", enc(brain)),
                Some(&payload),
                true,
            ),
            "push",
            force,
            kept_total,
        )
    } else {
        let pack = build_pack(&store)
            .unwrap_or_else(|e| fail(&format!("could not build store pack: {e}"), None));
        if pack.len() as u64 > MAX_PACK_BYTES {
            fail_snapshot_limit(
                &format!(
                    "canonical store pack is {} — the hub caps one pack at {}",
                    human_size(pack.len() as u64),
                    human_size(MAX_PACK_BYTES)
                ),
                &stats.largest,
                json!({ "limitBytes": MAX_PACK_BYTES, "packBytes": pack.len() }),
            );
        }
        let sha256 = format!("{:x}", Sha256::digest(&pack));
        let mut meta = json!({ "sha256": sha256, "bytes": pack.len() });
        meta["withheld_paths"] = json!(withheld.paths);
        meta["kept_home_unlinked"] = json!(withheld.unlinked);
        if !force {
            if let Some(baseline) = &prior_baseline {
                meta["expected_head_seq"] = json!(baseline.head_seq);
            }
        }
        let presigned = ensure_ok(
            request(
                cfg,
                "POST",
                &format!("/api/hub/brains/{}/packs/presign", enc(brain)),
                Some(&meta),
                true,
            ),
            "prepare pack upload",
        );
        let url = presigned
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("hub returned no pack upload URL", None));
        put_presigned(
            cfg,
            url,
            presigned.get("headers").unwrap_or(&Value::Null),
            &pack,
        );
        let mut commit = meta;
        if force {
            commit["allow_shrink"] = json!(true);
        }
        commit_pack(cfg, brain, &commit, force, kept_total)
    };
    let s = r.get("indexed").cloned().unwrap_or(json!({}));
    let n = |k: &str| s.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    let mut human = format!(
        "pushed {file_count} files → indexed {} docs, {} edges ({} withheld, {} broken), {} assets",
        n("documents"),
        n("edges"),
        n("withheldEdges"),
        n("brokenEdges"),
        n("assets")
    );
    if !withheld.paths.is_empty() || withheld.unlinked > 0 {
        human.push_str(&format!(
            "\nlinks: {} withheld target name(s) declared; {} other kept-home file(s) stay unnamed",
            withheld.paths.len(),
            withheld.unlinked,
        ));
    }
    // What stayed home, reported alongside what rode.
    let mut data = r;
    let brain_id = data
        .get("brain")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .unwrap_or_else(|| {
            fail(
                "push committed but the hub returned no valid brain identity",
                None,
            )
        })
        .to_string();
    let brain_slug = data
        .get("slug")
        .and_then(Value::as_str)
        .filter(|value| valid_brain_slug(value))
        .or_else(|| {
            prior_baseline
                .as_ref()
                .map(|value| value.brain_slug.as_str())
        })
        .unwrap_or_else(|| {
            fail(
                "push committed but the hub returned no valid brain slug",
                None,
            )
        })
        .to_string();
    let head_seq = data
        .get("headSeq")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| fail("push committed but the hub returned no feed sequence", None));
    let feed_hash = data
        .get("feedHash")
        .and_then(Value::as_str)
        .filter(|value| canonical_sha256(value))
        .unwrap_or_else(|| {
            fail(
                "push committed but the hub returned no valid feed hash",
                None,
            )
        })
        .to_string();
    let pack_sha256 = data
        .get("packSha256")
        .and_then(Value::as_str)
        .filter(|value| canonical_sha256(value))
        .unwrap_or_else(|| {
            fail(
                "push committed but the hub returned no valid pack hash",
                None,
            )
        })
        .to_string();
    let snapshot_entries = entries_from_store(&store);
    let asset_declarations =
        crate::assets::parse_restore_manifest(store.assets.as_deref().map(str::as_bytes))
            .unwrap_or_else(|error| fail(&error, None));
    let next_baseline = SyncBaseline {
        version: 1,
        brain_id,
        brain_slug,
        head_seq,
        feed_hash: Some(feed_hash),
        pack_sha256: Some(pack_sha256),
        paths: expected_snapshot_hashes(&snapshot_entries, &asset_declarations, scope.as_ref()),
        withheld_paths: withheld.paths.clone(),
        kept_home_unlinked: withheld.unlinked,
        carried_kept_home_unlinked: prior_baseline
            .as_ref()
            .map(|baseline| baseline.carried_kept_home_unlinked)
            .unwrap_or(0)
            .min(withheld.unlinked),
    };
    write_sync_baseline(&root, &next_baseline).unwrap_or_else(|error| {
        fail(
            &format!(
                "push committed at feed sequence {head_seq}, but the local divergence baseline could not be updated: {error}"
            ),
            Some(json!({ "code": "baseline_write_failed", "headSeq": head_seq })),
        )
    });
    if let Some(object) = data.as_object_mut() {
        object.insert("baseline".into(), json!(SYNC_BASELINE_FILE));
    }
    if let (Some(scan), Some(object)) = (asset_secret_scan.as_ref(), data.as_object_mut()) {
        object.insert("assetSecretScan".into(), scan.to_json());
    }
    if stats.kept_home > 0 {
        human.push_str(&format!(
            "\n{} file(s) kept home (.sevralocal)",
            stats.kept_home
        ));
        if let Some(obj) = data.as_object_mut() {
            obj.insert("keptHome".into(), json!(stats.kept_home));
        }
    }
    if stats.catalogs_kept > 0 {
        human.push_str(&format!(
            "\n{} derived catalog(s) kept home (the hub rebuilds its own)",
            stats.catalogs_kept
        ));
        if let Some(obj) = data.as_object_mut() {
            obj.insert("catalogsKeptHome".into(), json!(stats.catalogs_kept));
        }
    }

    // The byte half of the asset story: the snapshot just ingested the
    // manifest, so every declared hash is now uploadable — ship what the hub
    // reports missing. Strictly after the commit (the hub refuses undeclared
    // hashes) and skippable for a metadata-only push.
    let manifest_assets = n("assets");
    if !skip_assets && manifest_assets > 0 {
        let sync = crate::assets::sync_after_push(cfg, brain, dir, scope.as_ref());
        if sync.uploaded > 0 {
            human.push_str(&format!(
                "\nassets: {} uploaded ({})",
                sync.uploaded,
                human_size(sync.uploaded_bytes)
            ));
        } else if sync.missing_local == 0 && sync.drifted == 0 {
            human.push_str(&format!("\nassets: all {manifest_assets} present"));
        }
        if sync.kept_home > 0 {
            human.push_str(&format!(
                "\nassets: {} kept home (.sevralocal)",
                sync.kept_home
            ));
        }
        if sync.missing_local > 0 || sync.drifted > 0 {
            human.push_str(&format!(
                "\nassets: {} missing locally, {} drifted — run `dbmd assets scan` and push again",
                sync.missing_local, sync.drifted
            ));
        }
        if let Some(obj) = data.as_object_mut() {
            obj.insert("assetSync".into(), sync.to_json());
        }
    }
    out_layout(&human, Some(data));
}

// --- query / get / graph -----------------------------------------------------

/// `query` takes its brain positionally or via `--brain` (the flag `push`
/// uses — the two commands must not disagree). With `--brain` present the
/// first positional is the search text; the belt-and-braces shape
/// `query <brain> <text> --brain <ref>` must agree with the flag.
pub fn resolve_query_target(
    flag: Option<String>,
    first: Option<String>,
    second: Option<String>,
) -> Result<(String, Option<String>), String> {
    match (flag, first, second) {
        (None, Some(brain), text) => Ok((brain, text)),
        // clap fills positionals in order, so second without first cannot occur.
        (None, None, _) => Err(
            "which brain? `sevra query <brain> [text]`, or `sevra query --brain <ref> [text]`"
                .into(),
        ),
        (Some(flag), None, text) => Ok((flag, text)),
        (Some(flag), Some(text), None) => Ok((flag, Some(text))),
        (Some(flag), Some(first), Some(text)) => {
            if first == flag {
                Ok((flag, Some(text)))
            } else {
                Err(format!(
                    "the brain was given twice and differs: '{first}' (positional) vs '{flag}' (--brain) — pass it once"
                ))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn query(
    cfg: &Config,
    brain: &str,
    text: Option<String>,
    type_: Option<String>,
    layer: Option<String>,
    meta_type: Option<String>,
    tag: Option<String>,
    order: Option<String>,
    limit: Option<u32>,
    where_: Option<String>,
) {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(q) = text {
        params.push(("q".into(), q));
    }
    for (k, v) in [
        ("type", type_),
        ("layer", layer),
        ("meta-type", meta_type),
        ("tag", tag),
        ("order", order),
        ("limit", limit.map(|n| n.to_string())),
    ] {
        if let Some(val) = v {
            params.push((k.into(), val));
        }
    }
    if let Some(w) = where_ {
        params.push(("where".into(), w));
    }
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/query?{qs}", enc(brain)),
            None,
            true,
        ),
        "query",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    out(
        &format!(
            "{} result(s):",
            r.get("total").and_then(|t| t.as_i64()).unwrap_or(0)
        ),
        None,
    );
    for d in r
        .get("results")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let sum = d
            .get("summary")
            .and_then(|s| s.as_str())
            .or_else(|| d.get("title").and_then(|t| t.as_str()))
            .unwrap_or("");
        out_layout(
            &format!(
                "  {}\t{}\t{}",
                terminal_safe(str_field(&d, "path")),
                terminal_safe(str_field(&d, "type")),
                terminal_safe(sum)
            ),
            None,
        );
    }
}

pub fn get(cfg: &Config, brain: &str, reference: &str) {
    let key = if reference.contains('/') || reference.to_lowercase().ends_with(".md") {
        "path"
    } else {
        "id"
    };
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!(
                "/api/hub/brains/{}/resolve?{key}={}",
                enc(brain),
                enc(reference)
            ),
            None,
            true,
        ),
        "get",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let d = r.get("document").cloned().unwrap_or(json!({}));
    let title = d
        .get("title")
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| str_field(&d, "path"));
    out_layout(
        &format!(
            "# {}\npath: {}\ntype: {}  meta-type: {}\nid: {}\n\n{}",
            terminal_safe(title),
            terminal_safe(str_field(&d, "path")),
            terminal_safe(str_field(&d, "type")),
            terminal_safe(str_field(&d, "metaType")),
            terminal_safe(str_field(&d, "dbmdId")),
            terminal_safe(str_field(&d, "body"))
        ),
        None,
    );
}

pub fn graph(cfg: &Config, brain: &str, path: &str, dir: Option<String>) {
    // clap's value_parser already constrained --dir to in|out|both.
    let dir = dir.unwrap_or_else(|| "both".into());
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!(
                "/api/hub/brains/{}/graph?path={}&dir={}",
                enc(brain),
                enc(path),
                enc(&dir)
            ),
            None,
            true,
        ),
        "graph",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let edges = |k: &str| {
        r.get(k)
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
    };
    let back = edges("backlinks");
    out(&format!("backlinks ({}):", back.len()), None);
    for e in back {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) {
            ""
        } else {
            " (broken)"
        };
        out(&format!("  ← {}{broken}", str_field(&e, "srcPath")), None);
    }
    let outl = edges("outlinks");
    out(&format!("outlinks ({}):", outl.len()), None);
    for e in outl {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) {
            ""
        } else {
            " (broken)"
        };
        out(&format!("  → {}{broken}", str_field(&e, "dstPath")), None);
    }
}

// --- grants ------------------------------------------------------------------

pub fn grant(cfg: &Config, brain: &str, email: &str, write: bool) {
    let capability = if write { "write" } else { "read" };
    let body = json!({ "email": email, "capability": capability });
    let r = ensure_ok(
        request(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/grants", enc(brain)),
            Some(&body),
            true,
        ),
        "grant",
    );
    if r.get("pending").and_then(|p| p.as_bool()).unwrap_or(false) {
        out(&format!("invited {email} to {brain} ({capability}) — they get access when they sign up free"), Some(r));
    } else {
        out(
            &format!("granted {capability} on {brain} to {email}"),
            Some(r),
        );
    }
}

pub fn grants(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/grants", enc(brain)),
            None,
            true,
        ),
        "grants",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let list = r
        .get("grants")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        out("no grants", None);
        return;
    }
    for g in list {
        out_layout(
            &format!(
                "  {}\t{}\t{}",
                terminal_safe(str_field(&g, "email")),
                terminal_safe(str_field(&g, "capability")),
                terminal_safe(str_field(&g, "id"))
            ),
            None,
        );
    }
}

pub fn revoke(cfg: &Config, brain: &str, grant_id: &str) {
    ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/grants/{}", enc(brain), enc(grant_id)),
            None,
            true,
        ),
        "revoke",
    );
    out(
        &format!("revoked grant {grant_id}"),
        Some(json!({ "revoked": true })),
    );
}

pub fn shared(cfg: &Config) {
    let r = ensure_ok(request(cfg, "GET", "/api/hub/shared", None, true), "shared");
    if json_mode() {
        out("", Some(r));
        return;
    }
    let list = r
        .get("shared")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        out("nothing shared with you", None);
        return;
    }
    for b in list {
        out_layout(
            &format!(
                "  {}\t{}\t{}\t{}",
                terminal_safe(str_field(&b, "slug")),
                terminal_safe(str_field(&b, "id")),
                terminal_safe(str_field(&b, "capability")),
                terminal_safe(str_field(&b, "name"))
            ),
            None,
        );
    }
}

// --- publish / unpublish / inbox / export ------------------------------------

pub fn publish(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/publish", enc(brain)),
            None,
            true,
        ),
        "publish",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let layout_notes: Vec<String> = r
        .get("layoutErrors")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|e| format!("skipped (layout: site): {}", str_field(e, "message")))
        .collect();
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 {
        for m in &layout_notes {
            out(m, None);
        }
        out("nothing public to publish yet — make the brain public (`sevra` dashboard) or mark records `visibility: public`, then publish again.", None);
        return;
    }
    let url = str_field(&r, "url");
    let safe_url = terminal_safe(url);
    out(&format!("published {count} page(s) → {url}"), None);
    for p in r
        .get("published")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        out_layout(
            &format!(
                "  {safe_url}/{}\t{}",
                terminal_safe(str_field(&p, "pageSlug")),
                terminal_safe(str_field(&p, "title"))
            ),
            None,
        );
    }
    for m in &layout_notes {
        out(&format!("  {m}"), None);
    }
    let gated = r
        .get("gatedPages")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    if !gated.is_empty() {
        let paths = gated
            .iter()
            .map(|g| str_field(g, "docPath").to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out(&format!("  {} record(s) gated by audience — served behind Sign in with Sevra, never on public surfaces: {paths}", gated.len()), None);
    }
}

pub fn unpublish(cfg: &Config, brain: &str) {
    ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/publish", enc(brain)),
            None,
            true,
        ),
        "unpublish",
    );
    out(
        &format!("unpublished {brain} (public pages pulled)"),
        Some(json!({ "unpublished": true })),
    );
}

pub fn inbox(cfg: &Config, action: &str, brain: &str) {
    // clap's value_parser already constrained the action to list|drain.
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/inbox?limit=200", enc(brain)),
            None,
            true,
        ),
        "inbox",
    );
    if json_mode() || action == "drain" {
        // drain prints the full payload as JSON regardless of mode (the BYO
        // agent's read half).
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
        return;
    }
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 {
        out("inbox empty — no submissions.", None);
        return;
    }
    out(&format!("{count} submission(s):"), None);
    for it in r
        .get("items")
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default()
    {
        out(
            &format!(
                "  {}  {}  {}  {}",
                it.get("created").and_then(|c| c.as_str()).unwrap_or("-"),
                it.get("app").and_then(|a| a.as_str()).unwrap_or("-"),
                str_field(&it, "submittedBy"),
                str_field(&it, "path")
            ),
            None,
        );
    }
}

/// Normalize + contain: the resolved write path must stay inside `root`.
pub(crate) fn contained(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() || rel.contains('\0') {
        return None;
    }
    let mut full = root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => full.push(c),
            _ => return None, // .. / root / prefix — reject outright
        }
    }
    if full == root {
        return None;
    }
    Some(full)
}

#[derive(Default)]
struct ExportManifestNode {
    file: bool,
    children: BTreeMap<String, (String, ExportManifestNode)>,
}

fn windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper.strip_prefix("COM").is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
        || upper.strip_prefix("LPT").is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

/// One deterministic cross-platform filename key. APFS/HFS+ canonicalize
/// Unicode before comparing case; doing the same on every host turns an alias
/// into a preflight refusal instead of silent last-writer-wins data loss.
pub(crate) fn portable_component_key(component: &str) -> String {
    component.nfd().flat_map(char::to_lowercase).nfd().collect()
}

pub(crate) fn validate_portable_asset_path(path: &str) -> Result<(), String> {
    let components = portable_export_components(path)?;
    let keys: Vec<String> = components
        .iter()
        .map(|component| portable_component_key(component))
        .collect();
    let leaf = keys.last().expect("portable path has one component");
    let whole = keys.join("/");
    if matches!(whole.as_str(), "db.md" | "assets.jsonl" | ".sevralocal")
        || leaf.ends_with(".md")
        || matches!(
            keys.first().map(String::as_str),
            Some("feed" | "blobs" | "packs" | "pub" | "meta")
        )
    {
        return Err(format!(
            "refusing reserved asset path in export manifest: {}",
            terminal_safe(path)
        ));
    }
    Ok(())
}

pub(crate) fn portable_export_components(path: &str) -> Result<Vec<&str>, String> {
    if path.is_empty()
        || path.len() > 1024
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\0')
    {
        return Err(format!(
            "refusing unsafe export path: {}",
            terminal_safe(path)
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!(
                "refusing non-normalized export path: {}",
                terminal_safe(path)
            ));
        }
        if component.len() > 255 || portable_component_key(component).len() > 255 {
            return Err(format!(
                "refusing non-portable oversized export component: {}",
                terminal_safe(path)
            ));
        }
        if component.starts_with('.') {
            return Err(format!(
                "refusing hidden control component in export path: {}",
                terminal_safe(path)
            ));
        }
        if component.ends_with(['.', ' ']) {
            return Err(format!(
                "refusing non-portable export path with a trailing dot or space: {}",
                terminal_safe(path)
            ));
        }
        if component
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'))
        {
            return Err(format!(
                "refusing non-portable export path: {}",
                terminal_safe(path)
            ));
        }
        if windows_device_name(component) {
            return Err(format!(
                "refusing reserved device name in export path: {}",
                terminal_safe(path)
            ));
        }
        components.push(component);
    }
    let normalized_len = components
        .iter()
        .map(|component| portable_component_key(component).len())
        .sum::<usize>()
        .saturating_add(components.len().saturating_sub(1));
    if normalized_len > 1024 {
        return Err(format!(
            "refusing non-portable oversized export path: {}",
            terminal_safe(path)
        ));
    }
    Ok(components)
}

/// Validate the complete remote name set against one portable filesystem
/// model. This runs on every host, not just Windows: a hosted brain must be
/// exportable without aliases or data loss on every supported client.
fn validate_export_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let mut root = ExportManifestNode::default();
    for path in paths {
        let components = portable_export_components(path)?;
        let mut node = &mut root;
        for (index, component) in components.iter().enumerate() {
            if node.file {
                return Err(format!(
                    "refusing file/directory prefix collision in export manifest: {}",
                    terminal_safe(path)
                ));
            }
            let portable_key = portable_component_key(component);
            let child = node
                .children
                .entry(portable_key)
                .or_insert_with(|| ((*component).to_string(), ExportManifestNode::default()));
            if child.0 != *component {
                return Err(format!(
                    "refusing case-alias collision in export manifest: {}",
                    terminal_safe(path)
                ));
            }
            node = &mut child.1;
            if index + 1 == components.len() {
                if node.file {
                    return Err(format!(
                        "refusing duplicate export path: {}",
                        terminal_safe(path)
                    ));
                }
                if !node.children.is_empty() {
                    return Err(format!(
                        "refusing file/directory prefix collision in export manifest: {}",
                        terminal_safe(path)
                    ));
                }
                node.file = true;
            }
        }
    }
    Ok(())
}

fn validate_portable_core_path(path: &str) -> Result<(), String> {
    let components = portable_export_components(path)?;
    let keys: Vec<String> = components
        .iter()
        .map(|component| portable_component_key(component))
        .collect();
    let whole = keys.join("/");
    if whole == "db.md" && path != "DB.md" {
        return Err(format!(
            "refusing non-canonical DB.md control path: {}",
            terminal_safe(path)
        ));
    }
    if whole == "assets.jsonl" && path != "assets.jsonl" {
        return Err(format!(
            "refusing non-canonical assets.jsonl control path: {}",
            terminal_safe(path)
        ));
    }
    if whole == ".sevralocal" {
        return Err(format!(
            "refusing hosted .sevralocal control path: {}",
            terminal_safe(path)
        ));
    }
    if matches!(
        keys.first().map(String::as_str),
        Some("feed" | "blobs" | "packs" | "pub" | "meta")
    ) {
        return Err(format!(
            "refusing hosted internal namespace: {}",
            terminal_safe(path)
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_export_manifest(entries: &[(String, Vec<u8>)]) -> Result<(), String> {
    validate_export_paths(entries.iter().map(|(path, _)| path.as_str()))
}

/// Resolve every currently-existing destination component before content
/// installation. The capability-safe writer repeats these checks at commit
/// time; this pass guarantees all static symlink/type failures are reported
/// before any earlier file can be replaced.
fn preflight_export_paths<'a>(
    root: &Path,
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(
                "cannot securely use export root without following links: destination root is a symlink"
                    .to_string(),
            );
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(
                "cannot securely use export root: destination is not a directory".to_string(),
            );
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot inspect export root: {e}")),
    }

    for path in paths {
        let components = portable_export_components(path)?;
        let mut current = root.to_path_buf();
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let is_leaf = index + 1 == components.len();
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let kind = if is_leaf { "leaf" } else { "ancestor" };
                    return Err(format!(
                        "destination {kind} is a symlink: {}",
                        terminal_safe(path)
                    ));
                }
                Ok(metadata) if is_leaf && !metadata.is_file() => {
                    return Err(format!(
                        "destination leaf is not a regular file: {}",
                        terminal_safe(path)
                    ));
                }
                Ok(metadata) if !is_leaf && !metadata.is_dir() => {
                    return Err(format!(
                        "destination ancestor is not a directory: {}",
                        terminal_safe(path)
                    ));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => {
                    return Err(format!(
                        "cannot inspect export destination {}: {e}",
                        terminal_safe(path)
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn preflight_export_destinations(root: &Path, entries: &[(String, Vec<u8>)]) -> Result<(), String> {
    preflight_export_paths(root, entries.iter().map(|(path, _)| path.as_str()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportFingerprint {
    len: u64,
    modified: Option<std::time::SystemTime>,
    readonly: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
}

#[derive(Clone)]
enum InstalledState {
    File {
        fingerprint: ExportFingerprint,
        sha256: [u8; 32],
    },
    Missing,
}

struct ExportBackup {
    path: String,
    bytes: Option<Vec<u8>>,
    permissions: Option<std::fs::Permissions>,
    fingerprint: Option<ExportFingerprint>,
    installed: Option<InstalledState>,
}

fn export_fingerprint(metadata: &std::fs::Metadata) -> ExportFingerprint {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    ExportFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        readonly: metadata.permissions().readonly(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        mode: metadata.mode(),
    }
}

fn export_mode(permissions: &std::fs::Permissions) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = permissions;
        0o600
    }
}

fn held_file_state(
    root: &crate::safe_path::SafeDir,
    path: &str,
) -> Result<Option<(Vec<u8>, std::fs::Permissions, ExportFingerprint)>, String> {
    let Some(mut file) = root.open_relative(path).map_err(|error| {
        format!(
            "could not securely inspect export destination {}: {error}",
            terminal_safe(path)
        )
    })?
    else {
        return Ok(None);
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect existing export file: {error}"))?;
    if metadata.len() > MAX_STORE_BYTES {
        return Err("existing export file exceeds the 512 MB transaction limit".to_string());
    }
    let bytes = read_bounded(&mut file, MAX_STORE_BYTES)
        .map_err(|error| format!("could not read existing export file: {error}"))?;
    Ok(Some((
        bytes,
        metadata.permissions(),
        export_fingerprint(&metadata),
    )))
}

fn parent_directories(paths: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut directories = BTreeSet::new();
    for path in paths {
        let mut parts: Vec<&str> = path.split('/').collect();
        parts.pop();
        while !parts.is_empty() {
            directories.insert(parts.join("/"));
            parts.pop();
        }
    }
    let mut directories: Vec<String> = directories.into_iter().collect();
    directories.sort_by_key(|path| path.matches('/').count());
    directories
}

fn snapshot_held_destinations(
    root: &crate::safe_path::SafeDir,
    paths: &[String],
) -> Result<Vec<ExportBackup>, String> {
    let mut backups = Vec::with_capacity(paths.len());
    let mut total = 0u64;
    for path in paths {
        let (bytes, permissions, fingerprint) = match held_file_state(root, path)? {
            Some((bytes, permissions, fingerprint)) => {
                if bytes.len() as u64 > MAX_STORE_BYTES.saturating_sub(total) {
                    return Err(
                        "existing export files exceed the 512 MB transaction backup limit"
                            .to_string(),
                    );
                }
                total += bytes.len() as u64;
                (Some(bytes), Some(permissions), Some(fingerprint))
            }
            None => (None, None, None),
        };
        backups.push(ExportBackup {
            path: path.clone(),
            bytes,
            permissions,
            fingerprint,
            installed: None,
        });
    }
    Ok(backups)
}

fn snapshot_missing_destinations(paths: &[String]) -> Vec<ExportBackup> {
    paths
        .iter()
        .map(|path| ExportBackup {
            path: path.clone(),
            bytes: None,
            permissions: None,
            fingerprint: None,
            installed: None,
        })
        .collect()
}

fn verify_export_snapshot(
    root: &crate::safe_path::SafeDir,
    backups: &[ExportBackup],
) -> Result<(), String> {
    for backup in backups {
        let current = held_file_state(root, &backup.path)?;
        match (backup.bytes.as_ref(), backup.fingerprint.as_ref(), current) {
            (None, None, None) => {}
            (Some(expected_bytes), Some(expected_fingerprint), Some((bytes, _, fingerprint)))
                if expected_bytes == &bytes && expected_fingerprint == &fingerprint => {}
            _ => {
                return Err(format!(
                    "export destination changed after transaction preflight: {}",
                    terminal_safe(&backup.path)
                ));
            }
        }
    }
    Ok(())
}

fn capture_installed_state(
    root: &crate::safe_path::SafeDir,
    path: &str,
    expected_sha256: [u8; 32],
) -> Result<InstalledState, String> {
    let Some((bytes, _, fingerprint)) = held_file_state(root, path)? else {
        return Err(format!(
            "export destination disappeared immediately after installation: {}",
            terminal_safe(path)
        ));
    };
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != expected_sha256 {
        return Err(format!(
            "export destination changed during installation: {}",
            terminal_safe(path)
        ));
    }
    Ok(InstalledState::File {
        fingerprint,
        sha256: actual,
    })
}

fn rollback_held_export(
    root: &crate::safe_path::SafeDir,
    backups: &[ExportBackup],
    created_directories: &[String],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for backup in backups.iter().rev() {
        let Some(installed) = &backup.installed else {
            continue;
        };
        let current = held_file_state(root, &backup.path);
        let unchanged = match (installed, current) {
            (
                InstalledState::File {
                    fingerprint: expected_fingerprint,
                    sha256: expected_sha256,
                },
                Ok(Some((bytes, _, fingerprint))),
            ) => {
                let sha256: [u8; 32] = Sha256::digest(&bytes).into();
                fingerprint == *expected_fingerprint && sha256 == *expected_sha256
            }
            (InstalledState::Missing, Ok(None)) => true,
            _ => false,
        };
        if !unchanged {
            errors.push(format!(
                "{}: refusing to clobber a concurrent edit during rollback",
                terminal_safe(&backup.path)
            ));
            continue;
        }
        let result = match &backup.bytes {
            Some(bytes) => {
                let permissions = backup
                    .permissions
                    .as_ref()
                    .expect("existing backup retains permissions");
                root.atomic_write(&backup.path, bytes, true, export_mode(permissions))
                    .and_then(|()| {
                        root.restore_permissions(
                            &backup.path,
                            export_mode(permissions),
                            permissions.readonly(),
                        )
                    })
            }
            None => root.remove_regular(&backup.path).map(|_| ()),
        };
        if let Err(error) = result {
            errors.push(format!("{}: {error}", terminal_safe(&backup.path)));
        }
    }
    for directory in created_directories.iter().rev() {
        if let Err(error) = root.remove_empty_dir(directory) {
            errors.push(format!("{}: {error}", terminal_safe(directory)));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn pull_journal_bytes(journal: &PullJournal) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(journal).expect("pull journal serializes");
    bytes.push(b'\n');
    bytes
}

fn validate_pull_journal(journal: PullJournal) -> Result<PullJournal, String> {
    if journal.version != 1 {
        return Err(format!(
            "unsupported {PULL_JOURNAL_FILE} version {}",
            journal.version
        ));
    }
    let suffix = journal
        .backup_dir
        .strip_prefix(PULL_BACKUP_PREFIX)
        .ok_or_else(|| format!("{PULL_JOURNAL_FILE} has an invalid backup directory"))?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{PULL_JOURNAL_FILE} has an invalid backup directory"
        ));
    }
    if !canonical_sha256(&journal.previous_baseline_sha256)
        || !canonical_sha256(&journal.next_baseline_sha256)
        || journal.entries.is_empty()
        || journal.entries.len() > MAX_STORE_FILES + 100_001
    {
        return Err(format!(
            "{PULL_JOURNAL_FILE} has invalid transaction bounds"
        ));
    }

    let mut paths = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for directory in &journal.created_directories {
        portable_export_components(directory)
            .map_err(|_| format!("{PULL_JOURNAL_FILE} contains an unsafe created directory"))?;
        if directory.starts_with(PULL_BACKUP_PREFIX)
            || directory == PULL_JOURNAL_FILE
            || directory == PULL_LOCK_FILE
            || !directories.insert(directory.clone())
        {
            return Err(format!(
                "{PULL_JOURNAL_FILE} contains an invalid created directory"
            ));
        }
    }
    let mut baseline_entry = None;
    for (index, entry) in journal.entries.iter().enumerate() {
        if entry.path != SYNC_BASELINE_FILE {
            portable_export_components(&entry.path).map_err(|_| {
                format!(
                    "{PULL_JOURNAL_FILE} contains an unsafe path: {}",
                    terminal_safe(&entry.path)
                )
            })?;
        }
        if entry.path == PULL_JOURNAL_FILE
            || entry.path == PULL_LOCK_FILE
            || entry.path.starts_with(PULL_BACKUP_PREFIX)
            || !paths.insert(entry.path.clone())
        {
            return Err(format!(
                "{PULL_JOURNAL_FILE} contains a duplicate or internal path"
            ));
        }
        let old_complete = entry.backup.is_some()
            && entry.old_sha256.as_deref().is_some_and(canonical_sha256)
            && entry.old_mode.is_some()
            && entry.old_readonly.is_some();
        let old_empty = entry.backup.is_none()
            && entry.old_sha256.is_none()
            && entry.old_mode.is_none()
            && entry.old_readonly.is_none();
        if (!old_complete && !old_empty)
            || entry.old_mode.is_some_and(|mode| mode > 0o7777)
            || !entry.new_sha256.as_deref().is_none_or(canonical_sha256)
            || (old_empty && entry.new_sha256.is_none())
        {
            return Err(format!(
                "{PULL_JOURNAL_FILE} contains an invalid path state"
            ));
        }
        if old_complete && entry.backup.as_deref() != Some(&format!("{index:08x}")) {
            return Err(format!(
                "{PULL_JOURNAL_FILE} contains an invalid backup address"
            ));
        }
        if entry.path == SYNC_BASELINE_FILE {
            baseline_entry = Some(entry);
        }
    }
    let Some(baseline_entry) = baseline_entry else {
        return Err(format!("{PULL_JOURNAL_FILE} has no baseline commit marker"));
    };
    if baseline_entry.old_sha256.as_deref() != Some(&journal.previous_baseline_sha256)
        || baseline_entry.new_sha256.as_deref() != Some(&journal.next_baseline_sha256)
    {
        return Err(format!(
            "{PULL_JOURNAL_FILE} baseline marker does not match its transaction"
        ));
    }
    if journal.created_directories.iter().any(|directory| {
        let prefix = format!("{directory}/");
        !paths.iter().any(|path| path.starts_with(&prefix))
    }) {
        return Err(format!(
            "{PULL_JOURNAL_FILE} names a directory outside its mutation paths"
        ));
    }
    Ok(journal)
}

fn load_pull_journal(root: &crate::safe_path::SafeDir) -> Result<Option<PullJournal>, String> {
    let Some(mut file) = root
        .open_relative(PULL_JOURNAL_FILE)
        .map_err(|error| format!("cannot securely open {PULL_JOURNAL_FILE}: {error}"))?
    else {
        return Ok(None);
    };
    let advertised = file
        .metadata()
        .map_err(|error| format!("cannot inspect {PULL_JOURNAL_FILE}: {error}"))?
        .len();
    if advertised > MAX_PULL_JOURNAL_BYTES {
        return Err(format!("{PULL_JOURNAL_FILE} exceeds its 64 MiB limit"));
    }
    let bytes = read_bounded(&mut file, MAX_PULL_JOURNAL_BYTES)
        .map_err(|error| format!("cannot read {PULL_JOURNAL_FILE}: {error}"))?;
    let journal: PullJournal = serde_json::from_slice(&bytes)
        .map_err(|_| format!("{PULL_JOURNAL_FILE} is not valid recovery JSON"))?;
    validate_pull_journal(journal).map(Some)
}

fn is_atomic_stage_name(name: &str) -> bool {
    name.strip_prefix(".sevra-new-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn cleanup_atomic_stages_in(
    directory: &crate::safe_path::SafeDir,
    label: &str,
) -> Result<(), String> {
    for entry in directory
        .entries()
        .map_err(|error| format!("cannot inspect {label} for interrupted atomic writes: {error}"))?
    {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        if !is_atomic_stage_name(name) {
            continue;
        }
        if entry.kind != crate::safe_path::EntryKind::File {
            return Err(format!(
                "interrupted atomic stage in {label} is not a regular file; refusing cleanup"
            ));
        }
        directory.remove_regular(name).map_err(|error| {
            format!("cannot remove interrupted atomic stage in {label}: {error}")
        })?;
    }
    Ok(())
}

fn open_pull_directory(
    root: &crate::safe_path::SafeDir,
    path: &str,
) -> Result<Option<crate::safe_path::SafeDir>, String> {
    let mut components = path.split('/');
    let Some(first) = components.next().filter(|component| !component.is_empty()) else {
        return Err("pull recovery directory is empty".to_string());
    };
    let mut directory = match root.open_dir(std::ffi::OsStr::new(first)) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "cannot securely open pull recovery directory {}: {error}",
                terminal_safe(path)
            ))
        }
    };
    for component in components {
        if component.is_empty() || component == "." || component == ".." {
            return Err("pull recovery directory is not normalized".to_string());
        }
        directory = match directory.open_dir(std::ffi::OsStr::new(component)) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "cannot securely open pull recovery directory {}: {error}",
                    terminal_safe(path)
                ))
            }
        };
    }
    Ok(Some(directory))
}

fn cleanup_pull_atomic_stages(
    root: &crate::safe_path::SafeDir,
    journal: Option<&PullJournal>,
) -> Result<(), String> {
    cleanup_atomic_stages_in(root, "the store root")?;
    let Some(journal) = journal else {
        return Ok(());
    };

    let mut directories = BTreeSet::new();
    directories.insert(journal.backup_dir.clone());
    for entry in &journal.entries {
        if let Some((parent, _)) = entry.path.rsplit_once('/') {
            directories.insert(parent.to_string());
        }
    }
    for path in directories {
        let Some(directory) = open_pull_directory(root, &path)? else {
            continue;
        };
        cleanup_atomic_stages_in(
            &directory,
            &format!("pull recovery directory {}", terminal_safe(&path)),
        )?;
    }
    Ok(())
}

fn cleanup_pull_transaction(
    root: &crate::safe_path::SafeDir,
    journal: &PullJournal,
) -> Result<(), String> {
    cleanup_pull_atomic_stages(root, Some(journal))?;
    let expected: BTreeSet<&str> = journal
        .entries
        .iter()
        .filter_map(|entry| entry.backup.as_deref())
        .collect();
    let backup = match root.open_dir(std::ffi::OsStr::new(&journal.backup_dir)) {
        Ok(backup) => Some(backup),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "cannot securely open pull recovery directory: {error}"
            ))
        }
    };
    if let Some(backup) = backup {
        for entry in backup
            .entries()
            .map_err(|error| format!("cannot inspect pull recovery directory: {error}"))?
        {
            let name = entry
                .name
                .to_str()
                .ok_or_else(|| "pull recovery directory contains a non-UTF-8 entry".to_string())?;
            if entry.kind != crate::safe_path::EntryKind::File || !expected.contains(name) {
                return Err(
                    "pull recovery directory contains an unexpected entry; refusing cleanup"
                        .to_string(),
                );
            }
            backup
                .remove_regular(name)
                .map_err(|error| format!("cannot remove pull recovery backup {name}: {error}"))?;
        }
        drop(backup);
        root.remove_empty_dir(&journal.backup_dir)
            .map_err(|error| format!("cannot remove pull recovery directory: {error}"))?;
    }
    root.remove_regular(PULL_JOURNAL_FILE)
        .map_err(|error| format!("cannot remove {PULL_JOURNAL_FILE}: {error}"))?;
    Ok(())
}

fn recover_ready_pull(
    root: &crate::safe_path::SafeDir,
    journal: &PullJournal,
) -> Result<(), String> {
    enum RecoveryAction {
        Restore {
            path: String,
            bytes: Vec<u8>,
            mode: u32,
            readonly: bool,
            current_exists: bool,
        },
        Remove(String),
    }

    cleanup_pull_atomic_stages(root, Some(journal))?;

    let mut actions = Vec::new();
    let mut backup_bytes = 0u64;
    for entry in &journal.entries {
        let current = held_file_state(root, &entry.path)?;
        let current_sha = current
            .as_ref()
            .map(|(bytes, _, _)| format!("{:x}", Sha256::digest(bytes)));
        if current_sha != entry.old_sha256 && current_sha != entry.new_sha256 {
            return Err(format!(
                "cannot recover interrupted pull because {} changed afterward; no files were restored",
                terminal_safe(&entry.path)
            ));
        }
        if let (Some(backup_name), Some(old_sha256), Some(mode), Some(readonly)) = (
            entry.backup.as_deref(),
            entry.old_sha256.as_deref(),
            entry.old_mode,
            entry.old_readonly,
        ) {
            let backup_path = format!("{}/{backup_name}", journal.backup_dir);
            let Some(mut backup) = root
                .open_relative(&backup_path)
                .map_err(|error| format!("cannot securely open pull recovery backup: {error}"))?
            else {
                return Err(format!(
                    "pull recovery backup is missing for {}",
                    terminal_safe(&entry.path)
                ));
            };
            let len = backup
                .metadata()
                .map_err(|error| format!("cannot inspect pull recovery backup: {error}"))?
                .len();
            if len > MAX_STORE_BYTES.saturating_sub(backup_bytes) {
                return Err("pull recovery backups exceed the 512 MB transaction limit".into());
            }
            let bytes = read_bounded(&mut backup, MAX_STORE_BYTES - backup_bytes)
                .map_err(|error| format!("cannot read pull recovery backup: {error}"))?;
            backup_bytes += bytes.len() as u64;
            if format!("{:x}", Sha256::digest(&bytes)) != old_sha256 {
                return Err(format!(
                    "pull recovery backup failed verification for {}",
                    terminal_safe(&entry.path)
                ));
            }
            actions.push(RecoveryAction::Restore {
                path: entry.path.clone(),
                bytes,
                mode,
                readonly,
                current_exists: current.is_some(),
            });
        } else if current.is_some() {
            actions.push(RecoveryAction::Remove(entry.path.clone()));
        }
    }

    for action in actions.into_iter().rev() {
        match action {
            RecoveryAction::Restore {
                path,
                bytes,
                mode,
                readonly,
                current_exists,
            } => {
                let restored = if current_exists {
                    root.atomic_write(&path, &bytes, true, mode)
                } else {
                    root.atomic_create(&path, &bytes, true, mode)
                };
                restored.map_err(|error| {
                    format!(
                        "could not restore {} from interrupted pull: {error}",
                        terminal_safe(&path)
                    )
                })?;
                root.restore_permissions(&path, mode, readonly)
                    .map_err(|error| format!("could not restore recovered mode: {error}"))?;
            }
            RecoveryAction::Remove(path) => {
                root.remove_regular(&path).map_err(|error| {
                    format!(
                        "could not remove {} from interrupted pull: {error}",
                        terminal_safe(&path)
                    )
                })?;
            }
        }
    }
    for directory in journal.created_directories.iter().rev() {
        match root.remove_empty_dir(directory) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                // A post-crash local write owns the directory now. Its paths
                // were already rejected above if they collided with a riding
                // mutation, so keep the non-empty directory intact.
            }
            Err(error) => {
                return Err(format!(
                    "could not clean created directory {} after interrupted pull: {error}",
                    terminal_safe(directory)
                ))
            }
        }
    }
    cleanup_pull_transaction(root, journal)
}

fn recover_pull_transaction(root: &crate::safe_path::SafeDir) -> Result<bool, String> {
    // An atomic journal create can be killed before the journal itself is
    // renamed into place. The store lock is held by every caller, so no live
    // Sevra writer can own one of these exact reserved staging names now.
    cleanup_pull_atomic_stages(root, None)?;
    let Some(journal) = load_pull_journal(root)? else {
        return Ok(false);
    };
    if journal.phase == PullJournalPhase::Preparing {
        cleanup_pull_transaction(root, &journal)?;
        return Ok(true);
    }
    let Some((baseline, _, _)) = held_file_state(root, SYNC_BASELINE_FILE)? else {
        return Err(format!(
            "cannot recover interrupted pull because {SYNC_BASELINE_FILE} is missing"
        ));
    };
    let baseline_sha256 = format!("{:x}", Sha256::digest(&baseline));
    if baseline_sha256 == journal.next_baseline_sha256
        && journal.next_baseline_sha256 != journal.previous_baseline_sha256
    {
        cleanup_pull_transaction(root, &journal)?;
        return Ok(true);
    }
    if baseline_sha256 != journal.previous_baseline_sha256 {
        return Err(format!(
            "cannot recover interrupted pull because {SYNC_BASELINE_FILE} changed afterward"
        ));
    }
    recover_ready_pull(root, &journal)?;
    Ok(true)
}

fn prepare_pull_transaction(
    root: &crate::safe_path::SafeDir,
    backups: &[ExportBackup],
    new_sha256: &[Option<String>],
    created_directories: Vec<String>,
) -> Result<PullJournal, String> {
    if backups.len() != new_sha256.len() {
        return Err("internal pull transaction state is inconsistent".to_string());
    }
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| "operating-system randomness unavailable".to_string())?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let backup_dir = format!("{PULL_BACKUP_PREFIX}{suffix}");
    let entries: Vec<PullJournalEntry> = backups
        .iter()
        .zip(new_sha256)
        .enumerate()
        .map(|(index, (backup, new_sha256))| PullJournalEntry {
            path: backup.path.clone(),
            backup: backup.bytes.as_ref().map(|_| format!("{index:08x}")),
            old_sha256: backup
                .bytes
                .as_ref()
                .map(|bytes| format!("{:x}", Sha256::digest(bytes))),
            old_mode: backup.permissions.as_ref().map(export_mode),
            old_readonly: backup
                .permissions
                .as_ref()
                .map(std::fs::Permissions::readonly),
            new_sha256: new_sha256.clone(),
        })
        .collect();
    let baseline = entries
        .iter()
        .find(|entry| entry.path == SYNC_BASELINE_FILE)
        .ok_or_else(|| "pull transaction has no baseline commit marker".to_string())?;
    let mut journal = validate_pull_journal(PullJournal {
        version: 1,
        phase: PullJournalPhase::Preparing,
        backup_dir,
        previous_baseline_sha256: baseline
            .old_sha256
            .clone()
            .ok_or_else(|| "pull transaction baseline disappeared".to_string())?,
        next_baseline_sha256: baseline
            .new_sha256
            .clone()
            .ok_or_else(|| "pull transaction has no next baseline".to_string())?,
        created_directories,
        entries,
    })?;
    root.atomic_create(
        PULL_JOURNAL_FILE,
        &pull_journal_bytes(&journal),
        false,
        0o600,
    )
    .map_err(|error| format!("cannot create durable pull journal: {error}"))?;

    let prepared = (|| -> Result<(), String> {
        let backup_dir = root
            .create_dir(&journal.backup_dir, 0o700)
            .map_err(|error| format!("cannot create pull recovery directory: {error}"))?;
        for (entry, backup) in journal.entries.iter().zip(backups) {
            if let (Some(name), Some(bytes)) = (entry.backup.as_deref(), backup.bytes.as_ref()) {
                backup_dir
                    .atomic_create(name, bytes, false, 0o600)
                    .map_err(|error| format!("cannot persist pull recovery backup: {error}"))?;
            }
        }
        drop(backup_dir);
        journal.phase = PullJournalPhase::Ready;
        root.atomic_write(
            PULL_JOURNAL_FILE,
            &pull_journal_bytes(&journal),
            false,
            0o600,
        )
        .map_err(|error| format!("cannot arm durable pull journal: {error}"))
    })();
    if let Err(error) = prepared {
        return match cleanup_pull_transaction(root, &journal) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "{error}; pull recovery metadata cleanup also failed: {cleanup}"
            )),
        };
    }
    Ok(journal)
}

fn install_complete_export(
    root: &crate::safe_path::SafeDir,
    entries: &[(String, Vec<u8>)],
    prepared: &mut crate::assets::PreparedRestore,
    mut backups: Vec<ExportBackup>,
    created_directories: Vec<String>,
    remove_paths: &[String],
    final_entry: Option<&(String, Vec<u8>)>,
) -> Result<Vec<ExportBackup>, String> {
    verify_export_snapshot(root, &backups)?;
    let mut completed = 0usize;
    for (path, content) in entries {
        let expected_missing = backups[completed].bytes.is_none();
        let write = if expected_missing {
            root.atomic_create(path, content, true, 0o600)
        } else {
            root.atomic_write(path, content, true, 0o600)
        };
        if let Err(error) = write {
            let rollback = rollback_held_export(root, &backups[..completed], &created_directories);
            return match rollback {
                Ok(()) => Err(format!(
                    "secure export write failed for {}: {error}; all writes were rolled back",
                    terminal_safe(path)
                )),
                Err(rollback_error) => Err(format!(
                    "secure export write failed for {}: {error}; rollback also failed: {rollback_error}",
                    terminal_safe(path)
                )),
            };
        }
        let sha256: [u8; 32] = Sha256::digest(content).into();
        match capture_installed_state(root, path, sha256) {
            Ok(installed) => backups[completed].installed = Some(installed),
            Err(error) => {
                let rollback =
                    rollback_held_export(root, &backups[..completed], &created_directories);
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => {
                        Err(format!("{error}; rollback also failed: {rollback_error}"))
                    }
                };
            }
        }
        completed += 1;
    }
    for asset in prepared.assets_mut() {
        let path = asset.path().to_string();
        let expected_missing = backups[completed].bytes.is_none();
        let write = if expected_missing {
            root.atomic_create_with(&path, true, 0o644, |destination| {
                asset.write_to(destination)
            })
        } else {
            root.atomic_write_with(&path, true, 0o644, |destination| {
                asset.write_to(destination)
            })
        };
        if let Err(error) = write {
            let rollback = rollback_held_export(root, &backups[..completed], &created_directories);
            return match rollback {
                Ok(()) => Err(format!(
                    "secure asset write failed for {}: {error}; all writes were rolled back",
                    terminal_safe(&path)
                )),
                Err(rollback_error) => Err(format!(
                    "secure asset write failed for {}: {error}; rollback also failed: {rollback_error}",
                    terminal_safe(&path)
                )),
            };
        }
        let installed = match held_file_state(root, &path) {
            Ok(Some(installed)) => installed,
            Ok(None) => {
                let error = format!("installed asset disappeared: {}", terminal_safe(&path));
                let rollback =
                    rollback_held_export(root, &backups[..completed], &created_directories);
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => {
                        Err(format!("{error}; rollback also failed: {rollback_error}"))
                    }
                };
            }
            Err(error) => {
                let rollback =
                    rollback_held_export(root, &backups[..completed], &created_directories);
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => {
                        Err(format!("{error}; rollback also failed: {rollback_error}"))
                    }
                };
            }
        };
        let digest = Sha256::digest(&installed.0);
        let actual_sha256 = format!("{digest:x}");
        let sha256: [u8; 32] = digest.into();
        backups[completed].installed = Some(InstalledState::File {
            fingerprint: installed.2,
            sha256,
        });
        if actual_sha256 != asset.sha256() {
            let error = format!(
                "installed asset changed during commit: {}",
                terminal_safe(&path)
            );
            let rollback = rollback_held_export(root, &backups[..=completed], &created_directories);
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => {
                    Err(format!("{error}; rollback also failed: {rollback_error}"))
                }
            };
        }
        completed += 1;
    }
    for path in remove_paths {
        let removed = root.remove_regular(path).map_err(|error| {
            format!(
                "secure pull removal failed for {}: {error}",
                terminal_safe(path)
            )
        });
        match removed {
            Ok(true) => backups[completed].installed = Some(InstalledState::Missing),
            Ok(false) => {
                let error = format!(
                    "pull destination disappeared during replacement: {}",
                    terminal_safe(path)
                );
                let rollback =
                    rollback_held_export(root, &backups[..completed], &created_directories);
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => {
                        Err(format!("{error}; rollback also failed: {rollback_error}"))
                    }
                };
            }
            Err(error) => {
                let rollback =
                    rollback_held_export(root, &backups[..completed], &created_directories);
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => {
                        Err(format!("{error}; rollback also failed: {rollback_error}"))
                    }
                };
            }
        }
        completed += 1;
    }
    if let Some((path, content)) = final_entry {
        let expected_missing = backups[completed].bytes.is_none();
        let write = if expected_missing {
            root.atomic_create(path, content, true, 0o600)
        } else {
            root.atomic_write(path, content, true, 0o600)
        };
        if let Err(error) = write {
            let rollback = rollback_held_export(root, &backups[..completed], &created_directories);
            return match rollback {
                Ok(()) => Err(format!(
                    "secure final metadata write failed for {}: {error}; all store changes were rolled back",
                    terminal_safe(path)
                )),
                Err(rollback_error) => Err(format!(
                    "secure final metadata write failed for {}: {error}; rollback also failed: {rollback_error}",
                    terminal_safe(path)
                )),
            };
        }
        let sha256: [u8; 32] = Sha256::digest(content).into();
        match capture_installed_state(root, path, sha256) {
            Ok(installed) => backups[completed].installed = Some(installed),
            Err(error) => {
                let rollback =
                    rollback_held_export(root, &backups[..completed], &created_directories);
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => {
                        Err(format!("{error}; rollback also failed: {rollback_error}"))
                    }
                };
            }
        }
    }
    Ok(backups)
}

#[cfg(test)]
fn snapshot_export_destinations(
    root: &Path,
    entries: &[(String, Vec<u8>)],
) -> Result<Vec<ExportBackup>, String> {
    let mut backups = Vec::with_capacity(entries.len());
    let mut total = 0u64;
    for (path, _) in entries {
        let bytes = match crate::safe_path::open_regular(root, path) {
            Ok(Some(mut file)) => {
                let remaining = MAX_STORE_BYTES.saturating_sub(total);
                let held_len = file
                    .metadata()
                    .map_err(|e| format!("could not inspect existing export file: {e}"))?
                    .len();
                if held_len > remaining {
                    return Err(
                        "existing export files exceed the 512 MB transaction backup limit"
                            .to_string(),
                    );
                }
                let bytes = read_bounded(&mut file, remaining)
                    .map_err(|e| format!("could not snapshot existing export file: {e}"))?;
                total += bytes.len() as u64;
                Some(bytes)
            }
            Ok(None) => None,
            Err(e) => {
                return Err(format!(
                    "could not securely snapshot export destination {}: {e}",
                    terminal_safe(path)
                ));
            }
        };
        backups.push(ExportBackup {
            path: path.clone(),
            bytes,
            permissions: None,
            fingerprint: None,
            installed: None,
        });
    }
    Ok(backups)
}

#[cfg(test)]
fn rollback_export(root: &Path, backups: &[ExportBackup]) -> Result<(), String> {
    let mut errors = Vec::new();
    for backup in backups.iter().rev() {
        let result = match &backup.bytes {
            Some(bytes) => {
                crate::safe_path::atomic_write(root, &backup.path, bytes, true, 0o600).map(|_| ())
            }
            None => crate::safe_path::remove_regular(root, &backup.path).map(|_| ()),
        };
        if let Err(error) = result {
            errors.push(format!("{}: {error}", terminal_safe(&backup.path)));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
fn install_export_entries_with<F>(
    root: &Path,
    entries: &[(String, Vec<u8>)],
    mut write: F,
) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[u8]) -> std::io::Result<()>,
{
    let backups = snapshot_export_destinations(root, entries)?;
    for (index, (path, content)) in entries.iter().enumerate() {
        if let Err(error) = write(root, path, content) {
            let rollback = rollback_export(root, &backups[..=index]);
            return match rollback {
                Ok(()) => Err(format!(
                    "secure export write failed for {}: {error}; prior writes were rolled back",
                    terminal_safe(path)
                )),
                Err(rollback_error) => Err(format!(
                    "secure export write failed for {}: {error}; rollback also failed: {rollback_error}",
                    terminal_safe(path)
                )),
            };
        }
    }
    Ok(())
}

fn entries_from_pack(bytes: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .unwrap_or_else(|e| fail(&format!("hub returned an invalid store pack: {e}"), None));
    if archive.is_empty() || archive.len() > MAX_PACK_FILES {
        fail("hub returned a store pack with an invalid file count", None);
    }
    let mut entries = Vec::with_capacity(archive.len());
    let mut seen = std::collections::HashSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .unwrap_or_else(|e| fail(&format!("could not read store pack entry: {e}"), None));
        if file.is_dir() {
            continue;
        }
        let path = file.name().to_string();
        if file.enclosed_name().is_none() || contained(Path::new("/store"), &path).is_none() {
            fail(&format!("refusing unsafe export path: {path}"), None);
        }
        if let Some(mode) = file.unix_mode() {
            let kind = mode & 0o170000;
            if kind != 0 && kind != 0o100000 {
                fail(&format!("refusing non-file ZIP entry: {path}"), None);
            }
        }
        if !seen.insert(path.clone()) {
            fail(&format!("refusing duplicate export path: {path}"), None);
        }
        let remaining = MAX_STORE_BYTES.saturating_sub(total);
        if file.size() > remaining {
            fail("store pack expands beyond the 512 MB limit", None);
        }
        // ZIP size fields are attacker-controlled. A forged-small central
        // directory entry must not turn `read_to_end` into an unbounded
        // decompression allocation before the post-read length check. The
        // stream itself is capped at the remaining whole-store budget.
        let content = read_bounded(&mut file, remaining)
            .unwrap_or_else(|e| fail(&format!("could not decompress {path}: {e}"), None));
        if content.len() as u64 != file.size() {
            fail(&format!("store pack entry length mismatch: {path}"), None);
        }
        total += content.len() as u64;
        entries.push((path, content));
    }
    if entries.is_empty() {
        fail("hub returned an empty store pack", None);
    }
    entries
}

fn read_bounded(reader: &mut impl Read, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let mut content = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut content)?;
    if content.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "entry expands beyond the remaining store limit",
        ));
    }
    Ok(content)
}

fn export_vault_names(response: &Value) -> Vec<String> {
    let Some(raw) = response.get("vaultItems") else {
        // A pre-vault hub did not send this additive field. Such a hub has no
        // vault items to name, so keep old-hub export compatibility.
        return Vec::new();
    };
    let items = raw
        .as_array()
        .unwrap_or_else(|| fail("hub returned malformed vault export metadata", None));
    let mut names = BTreeSet::new();
    for item in items {
        let name = item
            .as_str()
            .unwrap_or_else(|| fail("hub returned malformed vault export metadata", None));
        let name = parse_secret_name(name)
            .unwrap_or_else(|_| fail("hub returned an invalid vault name for export", None));
        if !names.insert(name) {
            fail("hub returned a duplicate vault name for export", None);
        }
    }
    names.into_iter().collect()
}

fn vault_export_entry(
    cfg: &Config,
    brain: &str,
    response: &Value,
    names: &[String],
    with_secrets: bool,
) -> (String, Vec<u8>) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut values = BTreeMap::new();
    if with_secrets {
        note(VAULT_EXPORT_WARNING);
        for name in names {
            let mut item = ensure_ok(
                request(
                    cfg,
                    "GET",
                    &format!(
                        "/api/hub/brains/{}/vault?name={}&purpose=export",
                        enc(brain),
                        enc(name)
                    ),
                    None,
                    true,
                ),
                "export vault item",
            );
            if item.get("name").and_then(Value::as_str) != Some(name.as_str()) {
                fail("hub returned a mismatched vault item during export", None);
            }
            let mut encoded = match item.get_mut("valueBase64").map(std::mem::take) {
                Some(Value::String(value)) => value,
                _ => fail("hub omitted a vault value during export", None),
            };
            let max_encoded = MAX_SECRET_VALUE_BYTES.div_ceil(3) * 4;
            if encoded.len() > max_encoded {
                let mut secret_bytes = encoded.into_bytes();
                secret_bytes.fill(0);
                fail("hub returned an oversized vault value during export", None);
            }
            let mut decoded = STANDARD.decode(&encoded).unwrap_or_else(|_| {
                encoded.clear();
                fail("hub returned an invalid vault value during export", None)
            });
            let valid = !decoded.is_empty()
                && decoded.len() <= MAX_SECRET_VALUE_BYTES
                && STANDARD.encode(&decoded) == encoded;
            decoded.fill(0);
            if !valid {
                encoded.clear();
                fail(
                    "hub returned a non-canonical vault value during export",
                    None,
                );
            }
            values.insert(name.clone(), encoded);
        }
    }

    let brain_id = response
        .get("brain")
        .and_then(Value::as_str)
        .unwrap_or(brain);
    let payload = VaultExportFile {
        version: 1,
        brain: brain_id,
        names,
        values_base64: with_secrets.then_some(&values),
    };
    let mut bytes = serde_json::to_vec_pretty(&payload)
        .unwrap_or_else(|_| fail("could not encode vault export metadata", None));
    bytes.push(b'\n');
    for value in values.into_values() {
        let mut secret_bytes = value.into_bytes();
        secret_bytes.fill(0);
    }
    (VAULT_EXPORT_FILE.to_string(), bytes)
}

pub fn export(
    cfg: &Config,
    brain: &str,
    dir: Option<String>,
    skip_assets: bool,
    with_secrets: bool,
) {
    let (r, requested) = request_snapshot(cfg, brain, None, true);
    if let Some((expected_seq, expected_hash)) = requested {
        let actual_seq = r.get("headSeq").and_then(Value::as_u64);
        let actual_hash = r.get("feedHash").and_then(Value::as_str);
        if actual_seq != Some(expected_seq) || actual_hash != expected_hash.as_deref() {
            fail(
                "hub returned an export other than the exact requested feed head",
                None,
            );
        }
    }
    // The default dir name comes from the hub's slug — validate it before it
    // becomes a path (don't trust the hub response).
    let remote_slug = r.get("slug").and_then(|s| s.as_str()).filter(|s| {
        !s.is_empty()
            && s.len() <= 63
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !s.starts_with('-')
            && !s.ends_with('-')
    });
    let local_slug: String = brain
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let local_slug = local_slug.trim_matches('-');
    let dir = dir.unwrap_or_else(|| {
        format!(
            "./{}-export",
            remote_slug.unwrap_or(if local_slug.is_empty() {
                "brain"
            } else {
                local_slug
            })
        )
    });
    let root = std::fs::canonicalize(".")
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(&dir);
    let root = normalize(&root);

    let entries: Vec<(String, Vec<u8>)> = if let Some(url) = r.get("url").and_then(Value::as_str) {
        let expected = r
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| fail("hub returned an invalid pack hash", None));
        let pack = get_presigned(cfg, url, MAX_PACK_BYTES);
        let actual = format!("{:x}", Sha256::digest(&pack));
        if actual != expected {
            fail("downloaded store pack failed SHA-256 verification", None);
        }
        entries_from_pack(pack)
    } else {
        let files = r
            .get("files")
            .and_then(Value::as_array)
            .unwrap_or_else(|| fail("hub returned neither a store pack nor files", None));
        files
            .iter()
            .map(|file| {
                let path = file
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("refusing malformed file path from hub", None));
                let content = file
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("refusing malformed file content from hub", None));
                (path.to_string(), content.as_bytes().to_vec())
            })
            .collect()
    };

    let asset_manifest = entries
        .iter()
        .find(|(path, _)| path == "assets.jsonl")
        .map(|(_, bytes)| bytes.as_slice());
    for (path, _) in &entries {
        validate_portable_core_path(path).unwrap_or_else(|error| fail(&error, None));
    }
    let asset_declarations = crate::assets::parse_restore_manifest(asset_manifest)
        .unwrap_or_else(|error| fail(&error, None));
    let vault_names = export_vault_names(&r);

    // Gate the complete namespace, including declared binary paths, before the
    // first filesystem mutation. Store files and assets share one portable
    // trie: neither half can alias or overwrite the other.
    for (path, _) in &entries {
        if contained(&root, path).is_none() {
            fail(
                &format!("refusing unsafe export path: {}", terminal_safe(path)),
                None,
            );
        }
    }
    let all_paths = || {
        entries
            .iter()
            .map(|(path, _)| path.as_str())
            .chain(asset_declarations.iter().map(|asset| asset.path.as_str()))
    };
    validate_export_paths(all_paths()).unwrap_or_else(|error| fail(&error, None));
    preflight_export_paths(&root, all_paths()).unwrap_or_else(|error| fail(&error, None));

    match std::fs::symlink_metadata(&root) {
        Ok(_) => fail(
            "export destination already exists; choose a new directory so export can publish atomically without replacing local data",
            None,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => fail(&format!("cannot inspect export destination: {error}"), None),
    }
    let mut prepared = if skip_assets {
        crate::assets::prepare_restore(cfg, brain, None, &[])
    } else {
        crate::assets::prepare_restore(cfg, brain, None, &asset_declarations)
    }
    .unwrap_or_else(|error| fail(&error, None));
    let vault_entry = vault_export_entry(cfg, brain, &r, &vault_names, with_secrets);

    let parent_path = root
        .parent()
        .unwrap_or_else(|| fail("export destination has no parent directory", None));
    let target_name = root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_else(|| fail("export destination name is not portable UTF-8", None));
    crate::safe_path::ensure_dir(parent_path, 0o755).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely create export parent without following links: {error}"),
            None,
        )
    });
    let parent = crate::safe_path::SafeDir::open(parent_path).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely hold export parent: {error}"),
            None,
        )
    });
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .unwrap_or_else(|_| fail("operating-system randomness unavailable", None));
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let stage_name = format!(".sevra-export-{suffix}");
    let stage = parent
        .create_dir(&stage_name, 0o700)
        .unwrap_or_else(|error| {
            fail(
                &format!("cannot create private export stage: {error}"),
                None,
            )
        });
    let mut paths: Vec<String> = all_paths().map(str::to_string).collect();
    paths.push(VAULT_EXPORT_FILE.to_string());
    let backups = snapshot_missing_destinations(&paths);
    let created_directories = parent_directories(paths.iter().cloned());
    let completed = match install_complete_export(
        &stage,
        &entries,
        &mut prepared,
        backups,
        created_directories.clone(),
        &[],
        Some(&vault_entry),
    ) {
        Ok(completed) => completed,
        Err(error) => {
            drop(stage);
            match parent.remove_empty_dir(&stage_name) {
                Ok(_) => fail(&error, None),
                Err(cleanup_error) => fail(
                    &format!("{error}; private stage cleanup also failed: {cleanup_error}"),
                    None,
                ),
            }
        }
    };
    drop(stage);
    if let Err(error) = parent.publish_dir_no_replace(&stage_name, target_name) {
        let rollback = parent
            .open_dir(std::ffi::OsStr::new(&stage_name))
            .map_err(|open_error| open_error.to_string())
            .and_then(|stage| {
                rollback_held_export(&stage, &completed, &created_directories)
                    .map_err(|rollback_error| rollback_error.to_string())
            })
            .and_then(|()| {
                parent
                    .remove_empty_dir(&stage_name)
                    .map(|_| ())
                    .map_err(|remove_error| remove_error.to_string())
            });
        match rollback {
            Ok(()) => fail(
                &format!(
                    "export destination appeared before atomic publish: {error}; private stage was removed"
                ),
                None,
            ),
            Err(rollback_error) => fail(
                &format!(
                    "export destination appeared before atomic publish: {error}; stage cleanup also failed: {rollback_error}"
                ),
                None,
            ),
        }
    }

    let mut data = r.as_object().cloned().unwrap_or_default();
    data.remove("files");
    data.remove("url");
    data.remove("vaultItems");
    data.insert("dir".into(), json!(dir));
    data.insert("fileCount".into(), json!(entries.len()));
    data.insert("vaultFile".into(), json!(VAULT_EXPORT_FILE));
    data.insert("vaultNames".into(), json!(vault_names));
    data.insert("vaultValuesIncluded".into(), json!(with_secrets));
    if with_secrets {
        data.insert("warning".into(), json!(VAULT_EXPORT_WARNING));
    }
    let mut human = format!(
        "exported {} file(s) → {}",
        entries.len(),
        terminal_safe(&dir)
    );

    if !skip_assets && asset_manifest.is_some() {
        let restore = prepared.report();
        if restore.restored > 0 {
            human.push_str(&format!(
                "\nassets: {} restored ({})",
                restore.restored,
                human_size(restore.restored_bytes)
            ));
        } else if restore.present > 0 {
            human.push_str(&format!("\nassets: all {} present", restore.present));
        }
        data.insert("assetRestore".into(), restore.to_json());
    }
    human.push_str(&format!(
        "\nvault: {} name(s) listed in {VAULT_EXPORT_FILE}; values {}",
        vault_names.len(),
        if with_secrets {
            "included (private file; handle as credentials)"
        } else {
            "not included"
        }
    ));
    out_layout(&human, Some(Value::Object(data)));
}

pub fn clone_brain(cfg: &Config, brain: &str, dir: Option<String>) {
    let snapshot = fetch_snapshot(cfg, brain, None);
    let dir = dir.unwrap_or_else(|| format!("./{}", snapshot.brain_slug));
    let root = normalize(
        &std::fs::canonicalize(".")
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&dir),
    );
    match std::fs::symlink_metadata(&root) {
        Ok(_) => fail(
            "clone destination already exists; choose a fresh directory",
            None,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => fail(&format!("cannot inspect clone destination: {error}"), None),
    }
    for (path, _) in &snapshot.entries {
        if contained(&root, path).is_none() {
            fail(
                &format!("refusing unsafe clone path: {}", terminal_safe(path)),
                None,
            );
        }
    }
    let baseline = SyncBaseline {
        version: 1,
        brain_id: snapshot.brain_id.clone(),
        brain_slug: snapshot.brain_slug.clone(),
        head_seq: snapshot.head_seq,
        feed_hash: snapshot.feed_hash.clone(),
        pack_sha256: snapshot.pack_sha256.clone(),
        paths: expected_snapshot_hashes(&snapshot.entries, &snapshot.assets, None),
        withheld_paths: snapshot.withheld_paths.clone(),
        kept_home_unlinked: snapshot.kept_home_unlinked,
        carried_kept_home_unlinked: snapshot.kept_home_unlinked,
    };
    validate_sync_baseline(baseline.clone())
        .unwrap_or_else(|error| fail(&format!("cannot record clone baseline: {error}"), None));
    let entries = snapshot.entries;
    let baseline_entry = (SYNC_BASELINE_FILE.to_string(), baseline_bytes(&baseline));
    let mut prepared = crate::assets::prepare_restore(cfg, brain, None, &snapshot.assets)
        .unwrap_or_else(|error| fail(&error, None));

    let parent_path = root
        .parent()
        .unwrap_or_else(|| fail("clone destination has no parent directory", None));
    let target_name = root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_else(|| fail("clone destination name is not portable UTF-8", None));
    crate::safe_path::ensure_dir(parent_path, 0o755).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely create clone parent without following links: {error}"),
            None,
        )
    });
    let parent = crate::safe_path::SafeDir::open(parent_path)
        .unwrap_or_else(|error| fail(&format!("cannot securely hold clone parent: {error}"), None));
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .unwrap_or_else(|_| fail("operating-system randomness unavailable", None));
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let stage_name = format!(".sevra-clone-{suffix}");
    let stage = parent
        .create_dir(&stage_name, 0o700)
        .unwrap_or_else(|error| fail(&format!("cannot create private clone stage: {error}"), None));
    let paths: Vec<String> = entries
        .iter()
        .map(|(path, _)| path.clone())
        .chain(snapshot.assets.iter().map(|asset| asset.path.clone()))
        .chain(std::iter::once(baseline_entry.0.clone()))
        .collect();
    let backups = snapshot_missing_destinations(&paths);
    let created_directories = parent_directories(paths.iter().cloned());
    let completed = match install_complete_export(
        &stage,
        &entries,
        &mut prepared,
        backups,
        created_directories.clone(),
        &[],
        Some(&baseline_entry),
    ) {
        Ok(completed) => completed,
        Err(error) => {
            drop(stage);
            match parent.remove_empty_dir(&stage_name) {
                Ok(_) => fail(&error, None),
                Err(cleanup_error) => fail(
                    &format!("{error}; private stage cleanup also failed: {cleanup_error}"),
                    None,
                ),
            }
        }
    };
    drop(stage);
    if let Err(error) = parent.publish_dir_no_replace(&stage_name, target_name) {
        let rollback = parent
            .open_dir(std::ffi::OsStr::new(&stage_name))
            .map_err(|open_error| open_error.to_string())
            .and_then(|stage| {
                rollback_held_export(&stage, &completed, &created_directories)
                    .map_err(|rollback_error| rollback_error.to_string())
            })
            .and_then(|()| {
                parent
                    .remove_empty_dir(&stage_name)
                    .map(|_| ())
                    .map_err(|remove_error| remove_error.to_string())
            });
        match rollback {
            Ok(()) => fail(
                &format!(
                    "clone destination appeared before atomic publish: {error}; private stage was removed"
                ),
                None,
            ),
            Err(rollback_error) => fail(
                &format!(
                    "clone destination appeared before atomic publish: {error}; stage cleanup also failed: {rollback_error}"
                ),
                None,
            ),
        }
    }

    let restore = prepared.report();
    let mut data = snapshot.response.as_object().cloned().unwrap_or_default();
    data.remove("files");
    data.remove("url");
    data.insert("dir".into(), json!(dir));
    data.insert("baseline".into(), json!(SYNC_BASELINE_FILE));
    data.insert("fileCount".into(), json!(baseline.paths.len()));
    data.insert("assetRestore".into(), restore.to_json());
    let mut human = format!(
        "cloned {} file(s) at feed sequence {} → {}",
        baseline.paths.len(),
        baseline.head_seq,
        terminal_safe(&dir)
    );
    if restore.restored > 0 {
        human.push_str(&format!(
            "\nassets: {} restored ({})",
            restore.restored,
            human_size(restore.restored_bytes)
        ));
    }
    if !baseline.withheld_paths.is_empty() || baseline.kept_home_unlinked > 0 {
        human.push_str(&format!(
            "\nlocal-only: {} linked target name(s) and {} other file(s) remain on the source machine; their hosted classification is preserved for future pushes",
            baseline.withheld_paths.len(),
            baseline.kept_home_unlinked,
        ));
    }
    out_layout(&human, Some(Value::Object(data)));
}

fn divergence_paths(
    baseline: &SyncBaseline,
    current: &BTreeMap<String, String>,
    scope: Option<&local::LocalScope>,
) -> Vec<String> {
    let keys: BTreeSet<String> = baseline
        .paths
        .keys()
        .filter(|path| path_rides(scope, path))
        .cloned()
        .chain(current.keys().cloned())
        .collect();
    keys.into_iter()
        .filter(|path| baseline.paths.get(path) != current.get(path))
        .collect()
}

fn fail_local_divergence(paths: &[String], dir: &str) -> ! {
    let shown = paths.len().min(20);
    let mut message = format!(
        "pull refused: the local store diverged from its clone baseline in {} path(s):",
        paths.len()
    );
    for path in &paths[..shown] {
        message.push_str(&format!("\n  {}", terminal_safe(path)));
    }
    if paths.len() > shown {
        message.push_str(&format!("\n  … and {} more", paths.len() - shown));
    }
    message.push_str(&format!(
        "\npush the local work first, reconcile it, or retry `sevra pull {dir} --force` only to discard it"
    ));
    fail(
        &message,
        Some(json!({ "code": "local_divergence", "paths": paths })),
    );
}

pub fn pull(cfg: &Config, dir: Option<String>, force: bool) {
    let dir = dir.unwrap_or_else(|| ".".to_string());
    let root = std::fs::canonicalize(&dir)
        .unwrap_or_else(|error| fail(&format!("cannot open pull directory {dir}: {error}"), None));
    let held_root = crate::safe_path::SafeDir::open(&root).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely hold pull directory: {error}"),
            None,
        )
    });
    let _pull_lock = held_root
        .lock_relative(PULL_LOCK_FILE)
        .unwrap_or_else(|error| fail(&format!("cannot lock pull state: {error}"), None));
    if recover_pull_transaction(&held_root).unwrap_or_else(|error| fail(&error, None)) {
        note("recovered an interrupted pull before checking the hub");
    }
    let baseline = load_sync_baseline(&root)
        .unwrap_or_else(|error| fail(&error, None))
        .unwrap_or_else(|| {
            fail(
                &format!(
                    "{dir} is not a Sevra clone ({SYNC_BASELINE_FILE} is missing); use `sevra clone <brain> [dir]` first"
                ),
                None,
            )
        });
    let scope = local::load(&root).unwrap_or_else(|error| fail(&error, None));
    let current = current_store_hashes(&root).unwrap_or_else(|error| fail(&error, None));
    let divergent = divergence_paths(&baseline, &current, scope.as_ref());
    if !divergent.is_empty() && !force {
        fail_local_divergence(&divergent, &dir);
    }

    let remote = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}", enc(&baseline.brain_id)),
            None,
            true,
        ),
        "check brain head",
    );
    let remote_id = remote
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("hub returned no valid brain identity", None));
    if remote_id != baseline.brain_id {
        fail("hub resolved the clone baseline to a different brain", None);
    }
    let remote_seq = remote
        .get("headSeq")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| fail("hub returned no valid feed sequence", None));
    let remote_hash = remote.get("feedHash").and_then(Value::as_str);
    if remote_seq > 0 && !remote_hash.is_some_and(canonical_sha256) {
        fail("hub returned an invalid feed hash", None);
    }
    if remote_seq < baseline.head_seq {
        fail(
            "hub feed sequence moved backwards; refusing to replace the clone",
            None,
        );
    }
    if !force && remote_seq == baseline.head_seq && remote_hash == baseline.feed_hash.as_deref() {
        out(
            &format!("already current at feed sequence {remote_seq}"),
            Some(json!({
                "brain": baseline.brain_id,
                "slug": baseline.brain_slug,
                "headSeq": remote_seq,
                "changed": false,
                "dir": dir,
            })),
        );
        return;
    }
    let exact_hash = remote_hash.unwrap_or_else(|| {
        fail(
            "the hosted brain has no durable snapshot to pull",
            Some(json!({ "headSeq": remote_seq })),
        )
    });
    let snapshot = fetch_snapshot(cfg, &baseline.brain_id, Some((remote_seq, exact_hash)));
    if snapshot.brain_id != baseline.brain_id {
        fail("exact snapshot belongs to a different brain", None);
    }

    let new_hashes = expected_snapshot_hashes(&snapshot.entries, &snapshot.assets, scope.as_ref());
    let carried_kept_home_unlinked =
        if snapshot.kept_home_unlinked >= baseline.kept_home_unlinked {
            baseline
                .carried_kept_home_unlinked
                .saturating_add(snapshot.kept_home_unlinked - baseline.kept_home_unlinked)
        } else {
            baseline
                .carried_kept_home_unlinked
                .saturating_sub(baseline.kept_home_unlinked - snapshot.kept_home_unlinked)
        }
        .min(snapshot.kept_home_unlinked);
    let next_baseline = SyncBaseline {
        version: 1,
        brain_id: snapshot.brain_id.clone(),
        brain_slug: snapshot.brain_slug.clone(),
        head_seq: snapshot.head_seq,
        feed_hash: snapshot.feed_hash.clone(),
        pack_sha256: snapshot.pack_sha256.clone(),
        paths: new_hashes.clone(),
        withheld_paths: snapshot.withheld_paths.clone(),
        kept_home_unlinked: snapshot.kept_home_unlinked,
        carried_kept_home_unlinked,
    };
    validate_sync_baseline(next_baseline.clone())
        .unwrap_or_else(|error| fail(&format!("cannot record pull baseline: {error}"), None));

    let entries: Vec<(String, Vec<u8>)> = snapshot
        .entries
        .into_iter()
        .filter(|(path, _)| path_rides(scope.as_ref(), path))
        .collect();
    let baseline_entry = (
        SYNC_BASELINE_FILE.to_string(),
        baseline_bytes(&next_baseline),
    );
    let riding_assets: Vec<_> = snapshot
        .assets
        .into_iter()
        .filter(|asset| path_rides(scope.as_ref(), &asset.path))
        .collect();
    let mut prepared =
        crate::assets::prepare_restore(cfg, &baseline.brain_id, Some(&held_root), &riding_assets)
            .unwrap_or_else(|error| fail(&error, None));
    let pending_assets: Vec<String> = prepared.pending_paths().map(str::to_string).collect();
    let new_paths: BTreeSet<&str> = new_hashes.keys().map(String::as_str).collect();
    let remove_paths: Vec<String> = current
        .keys()
        .filter(|path| !new_paths.contains(path.as_str()) && path_rides(scope.as_ref(), path))
        .cloned()
        .collect();
    let mut mutation_paths: Vec<String> = entries.iter().map(|(path, _)| path.clone()).collect();
    mutation_paths.extend(pending_assets.iter().cloned());
    mutation_paths.extend(remove_paths.iter().cloned());
    mutation_paths.push(baseline_entry.0.clone());
    preflight_export_paths(
        &root,
        mutation_paths
            .iter()
            .filter(|path| path.as_str() != SYNC_BASELINE_FILE)
            .map(String::as_str),
    )
    .unwrap_or_else(|error| fail(&error, None));
    let created_directories: Vec<String> = parent_directories(mutation_paths.iter().cloned())
        .into_iter()
        .filter(|directory| {
            !held_root
                .directory_exists_relative(directory)
                .unwrap_or_else(|error| {
                    fail(
                        &format!(
                            "cannot securely inspect pull directory {}: {error}",
                            terminal_safe(directory)
                        ),
                        None,
                    )
                })
        })
        .collect();
    let backups = snapshot_held_destinations(&held_root, &mutation_paths)
        .unwrap_or_else(|error| fail(&error, None));
    let riding_asset_hashes: BTreeMap<&str, &str> = riding_assets
        .iter()
        .map(|asset| (asset.path.as_str(), asset.sha256.as_str()))
        .collect();
    let mut mutation_sha256: Vec<Option<String>> = entries
        .iter()
        .map(|(_, content)| Some(format!("{:x}", Sha256::digest(content))))
        .collect();
    mutation_sha256.extend(pending_assets.iter().map(|path| {
        Some(
            riding_asset_hashes
                .get(path.as_str())
                .expect("pending asset came from riding declarations")
                .to_string(),
        )
    }));
    mutation_sha256.extend(remove_paths.iter().map(|_| None));
    mutation_sha256.push(Some(format!("{:x}", Sha256::digest(&baseline_entry.1))));
    let journal =
        prepare_pull_transaction(&held_root, &backups, &mutation_sha256, created_directories)
            .unwrap_or_else(|error| fail(&error, None));
    let install = install_complete_export(
        &held_root,
        &entries,
        &mut prepared,
        backups,
        Vec::new(),
        &remove_paths,
        Some(&baseline_entry),
    );
    if let Err(error) = install {
        let recovery = recover_pull_transaction(&held_root);
        match recovery {
            Ok(_) => fail(&error, None),
            Err(recovery_error) => fail(
                &format!("{error}; durable pull recovery also failed: {recovery_error}"),
                None,
            ),
        }
    }
    cleanup_pull_transaction(&held_root, &journal).unwrap_or_else(|error| {
        fail(
            &format!(
                "pull committed, but recovery metadata cleanup failed: {error}; rerun pull to finish cleanup"
            ),
            None,
        )
    });

    let restore = prepared.report();
    let mut data = snapshot.response.as_object().cloned().unwrap_or_default();
    data.remove("files");
    data.remove("url");
    data.insert("dir".into(), json!(dir));
    data.insert("changed".into(), json!(true));
    data.insert(
        "discardedLocalDivergence".into(),
        json!(force && !divergent.is_empty()),
    );
    data.insert("removed".into(), json!(remove_paths));
    data.insert("assetRestore".into(), restore.to_json());
    let mut human = format!(
        "pulled feed sequence {} → {} file(s) current",
        next_baseline.head_seq,
        next_baseline.paths.len()
    );
    if force && !divergent.is_empty() {
        human.push_str(&format!(
            "\nforce: discarded local divergence in {} path(s)",
            divergent.len()
        ));
    }
    if restore.restored > 0 {
        human.push_str(&format!(
            "\nassets: {} restored ({})",
            restore.restored,
            human_size(restore.restored_bytes)
        ));
    }
    out_layout(&human, Some(Value::Object(data)));
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// --- secrets (the vault) -------------------------------------------------------
//
// Server-custodied values that follow the brain across machines. The security contract,
// locked by tests: the VALUE is read from stdin only — never argv (argv is
// visible to every process on the machine), never echoed back on any path
// (prompts, errors, --json included). NAMES are public metadata (records
// declare them; the dashboard lists them) and are clap-validated to the hub's
// exact shape before any request.

/// clap value_parser for a vault NAME — the hub's gate, mirrored exactly:
/// `^[A-Za-z][A-Za-z0-9_-]{0,63}$`. Refusal is a usage error (exit 2) before any I/O.
pub fn parse_secret_name(s: &str) -> Result<String, String> {
    let ok = matches!(s.as_bytes().first(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        && s.len() <= 64
        && s.bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    if ok {
        Ok(s.to_string())
    } else {
        Err(
            "vault names start with a letter and use only letters, numbers, underscores, or hyphens (at most 64 characters; e.g. stripe-key)"
                .into(),
        )
    }
}

/// Trim exactly ONE trailing newline (`\n` or `\r\n`) — so `printf %s "$V" |`
/// and `echo "$V" |` both deliver the same value, while a value that really
/// ends in a newline can still be sent by appending one more.
fn trim_one_newline(mut value: Vec<u8>) -> Vec<u8> {
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    value
}

/// Read the secret VALUE: prompted on the controlling terminal with echo OFF
/// when stdin is a TTY (rpassword talks to /dev/tty directly, so `--json`
/// stdout stays clean), else read whole from piped stdin. Never from argv;
/// never echoed — the refusal messages below name sizes and shapes, never
/// bytes.
fn secret_value_from_stdin(name: &str) -> Vec<u8> {
    use std::io::{IsTerminal, Read};
    let mut value = if std::io::stdin().is_terminal() {
        match rpassword::prompt_password(format!("value for {name} (input hidden): ")) {
            Ok(v) => v.into_bytes(),
            Err(e) => fail(
                &format!(
                    "could not read from the terminal: {e} — pipe the value instead: printf %s \"$VALUE\" | sevra secrets set <brain> {name}"
                ),
                None,
            ),
        }
    } else {
        let stdin = std::io::stdin();
        let mut bytes = Vec::with_capacity(MAX_SECRET_STDIN_BYTES.min(8192));
        let mut limited = stdin.lock().take((MAX_SECRET_STDIN_BYTES + 1) as u64);
        if let Err(e) = limited.read_to_end(&mut bytes) {
            fail(
                &format!("could not read the value bytes from stdin: {e}"),
                None,
            );
        }
        if bytes.len() > MAX_SECRET_STDIN_BYTES {
            fail(
                &format!(
                    "the value is too large — the hub caps one vault item at {MAX_SECRET_VALUE_BYTES} bytes"
                ),
                None,
            );
        }
        trim_one_newline(bytes)
    };
    if value.is_empty() {
        fail(
            &format!(
                "empty value — pipe the secret on stdin: printf %s \"$VALUE\" | sevra secrets set <brain> {name}"
            ),
            None,
        );
    }
    if value.len() > MAX_SECRET_VALUE_BYTES {
        fail(
            &format!(
                "the value is {} bytes — the hub caps one vault item at {MAX_SECRET_VALUE_BYTES} bytes",
                value.len()
            ),
            None,
        );
    }
    value.shrink_to_fit();
    value
}

pub fn secrets_list(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/vault", enc(brain)),
            None,
            true,
        ),
        "secrets list",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let names: Vec<&str> = r
        .get("items")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    if names.is_empty() {
        out(
            "the brain vault is empty — printf %s \"$VALUE\" | sevra secrets set <brain> NAME",
            None,
        );
    } else {
        out(
            &format!(
                "vault items ({}; values stay hidden): {}",
                names.len(),
                names.join(", ")
            ),
            None,
        );
    }
}

pub fn secrets_set(cfg: &Config, brain: &str, name: &str, value_in_argv: bool) {
    if value_in_argv {
        // The trap arguments exist so this refusal happens WITHOUT echoing
        // what clap's own unexpected-argument error would have printed. The
        // argv exposure itself already happened at the OS level — say so.
        usage_fail(
            "the secret value is never taken from the command line (argv is visible to every process on the machine; it was NOT echoed here, but treat it as exposed). Pipe it on stdin instead: printf %s \"$VALUE\" | sevra secrets set <brain> NAME",
        );
    }
    // Before the prompt: never ask for a secret this process cannot send.
    if cfg.key.is_none() {
        fail(NOT_LOGGED_IN, None);
    }
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut value = secret_value_from_stdin(name);
    let body = json!({ "name": name, "valueBase64": STANDARD.encode(&value) });
    value.fill(0);
    let r = ensure_ok(
        request(
            cfg,
            "PUT",
            &format!("/api/hub/brains/{}/vault", enc(brain)),
            Some(&body),
            true,
        ),
        "secrets set",
    );
    out(&format!("set vault item {name} on {brain}"), Some(r));
}

fn stdout_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
        || (cfg!(debug_assertions) && std::env::var("SEVRA_TEST_STDOUT_TTY").as_deref() == Ok("1"))
}

pub fn secrets_get(cfg: &Config, brain: &str, name: &str, reveal: bool) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    if cfg.key.is_none() {
        fail(NOT_LOGGED_IN, None);
    }
    let terminal = stdout_is_terminal();
    if terminal && !reveal {
        usage_fail(
            "refusing to print a vault value to a terminal — pass --reveal, or pipe stdout to the consuming process",
        );
    }

    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/vault?name={}", enc(brain), enc(name)),
            None,
            true,
        ),
        "secrets get",
    );
    let encoded = r
        .get("valueBase64")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("secrets get failed: the hub omitted valueBase64", None));
    let max_encoded = MAX_SECRET_VALUE_BYTES.div_ceil(3) * 4;
    if encoded.len() > max_encoded {
        fail(
            &format!(
                "secrets get failed: the hub returned more than {MAX_SECRET_VALUE_BYTES} bytes"
            ),
            None,
        );
    }
    let mut value = STANDARD
        .decode(encoded)
        .unwrap_or_else(|_| fail("secrets get failed: the hub returned invalid base64", None));
    if value.is_empty()
        || value.len() > MAX_SECRET_VALUE_BYTES
        || STANDARD.encode(&value) != encoded
    {
        value.fill(0);
        fail(
            "secrets get failed: the hub returned a non-canonical or invalid vault value",
            None,
        );
    }

    if json_mode() {
        value.fill(0);
        out("", Some(r));
        return;
    }
    if terminal {
        let human = match std::str::from_utf8(&value) {
            Ok(text) => format!(
                "{}: {}",
                terminal_safe(name),
                terminal_safe(text)
            ),
            Err(_) => format!(
                "{} is binary ({} bytes); pipe this command to a file, or use --json --reveal for base64",
                terminal_safe(name),
                value.len()
            ),
        };
        value.fill(0);
        out_layout(&human, None);
        return;
    }

    let result = {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&value).and_then(|_| stdout.flush())
    };
    value.fill(0);
    if let Err(error) = result {
        fail(
            &format!("could not write the vault value to stdout: {error}"),
            None,
        );
    }
}

pub fn secrets_delete(cfg: &Config, brain: &str, name: &str) {
    let body = json!({ "name": name });
    let r = ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/vault", enc(brain)),
            Some(&body),
            true,
        ),
        "secrets rm",
    );
    let mut data = r.as_object().cloned().unwrap_or_default();
    data.insert("name".into(), json!(name));
    out(
        &format!("removed vault item {name} from {brain}"),
        Some(Value::Object(data)),
    );
}

fn utc_rfc3339_now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days algorithm, with Unix day zero shifted
    // to the proleptic Gregorian epoch. Avoids a platform/runtime dependency.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn load_adopt_journal(root: &crate::safe_path::SafeDir) -> Result<Option<AdoptJournal>, String> {
    let Some(mut file) = root
        .open_relative(ADOPT_JOURNAL_FILE)
        .map_err(|error| format!("cannot securely open {ADOPT_JOURNAL_FILE}: {error}"))?
    else {
        return Ok(None);
    };
    let len = file
        .metadata()
        .map_err(|error| format!("cannot inspect {ADOPT_JOURNAL_FILE}: {error}"))?
        .len();
    if len > MAX_ADOPT_JOURNAL_BYTES {
        return Err(format!("{ADOPT_JOURNAL_FILE} exceeds its 4 MiB limit"));
    }
    let bytes = read_bounded(&mut file, MAX_ADOPT_JOURNAL_BYTES)
        .map_err(|error| format!("cannot read {ADOPT_JOURNAL_FILE}: {error}"))?;
    let journal: AdoptJournal = serde_json::from_slice(&bytes)
        .map_err(|_| format!("{ADOPT_JOURNAL_FILE} is not valid journal JSON"))?;
    if journal.version != 1
        || journal.brain_id.is_empty()
        || journal.brain_id.len() > 200
        || journal.brain_id.chars().any(char::is_control)
        || journal.mappings.len() > 256
        || journal.paths.len() > MAX_STORE_FILES
    {
        return Err(format!("{ADOPT_JOURNAL_FILE} has an invalid shape"));
    }
    for (hash, name) in &journal.mappings {
        if !canonical_sha256(hash) || parse_secret_name(name).is_err() {
            return Err(format!("{ADOPT_JOURNAL_FILE} has an invalid mapping"));
        }
    }
    for path in &journal.paths {
        portable_export_components(path)
            .map_err(|_| format!("{ADOPT_JOURNAL_FILE} has an unsafe path"))?;
        if !path.to_ascii_lowercase().ends_with(".md") {
            return Err(format!("{ADOPT_JOURNAL_FILE} names a non-markdown path"));
        }
    }
    Ok(Some(journal))
}

fn write_adopt_journal(
    root: &crate::safe_path::SafeDir,
    journal: &AdoptJournal,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(journal)
        .map_err(|_| format!("cannot encode {ADOPT_JOURNAL_FILE}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_ADOPT_JOURNAL_BYTES {
        return Err(format!("{ADOPT_JOURNAL_FILE} exceeds its 4 MiB limit"));
    }
    root.atomic_write(ADOPT_JOURNAL_FILE, &bytes, false, 0o600)
        .map_err(|error| format!("cannot persist {ADOPT_JOURNAL_FILE}: {error}"))
}

fn frontmatter_bounds(content: &str) -> Result<(usize, usize, &'static str), String> {
    let (mut cursor, newline) = if content.starts_with("---\r\n") {
        (5, "\r\n")
    } else if content.starts_with("---\n") {
        (4, "\n")
    } else {
        return Err("markdown has no leading YAML frontmatter".into());
    };
    while cursor <= content.len() {
        let next = content[cursor..]
            .find('\n')
            .map(|offset| cursor + offset)
            .unwrap_or(content.len());
        let line = content[cursor..next]
            .strip_suffix('\r')
            .unwrap_or(&content[cursor..next]);
        if line == "---" {
            return Ok((if newline == "\r\n" { 5 } else { 4 }, cursor, newline));
        }
        if next == content.len() {
            break;
        }
        cursor = next + 1;
    }
    Err("markdown has unterminated YAML frontmatter".into())
}

fn apply_redacted_provenance(
    content: &str,
    additions: &BTreeSet<RedactedProvenance>,
    updated_at: &str,
) -> Result<String, String> {
    let (open_end, close_start, newline) = frontmatter_bounds(content)?;
    let frontmatter = &content[open_end..close_start];
    let mut lines: Vec<String> = frontmatter
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_string())
        .collect();
    let mut updated_index = None;
    let mut redacted_index = None;
    let mut provenance = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        if line.starts_with("updated:") && updated_index.replace(index).is_some() {
            return Err("frontmatter has duplicate updated keys".into());
        }
        if let Some(raw) = line.strip_prefix("redacted:") {
            if redacted_index.replace(index).is_some() {
                return Err("frontmatter has duplicate redacted keys".into());
            }
            let raw = raw.trim();
            if raw.is_empty() {
                return Err("frontmatter redacted provenance must be an inline JSON array".into());
            }
            let existing: Vec<RedactedProvenance> = serde_json::from_str(raw)
                .map_err(|_| "frontmatter redacted provenance must be an inline JSON array")?;
            for entry in existing {
                if parse_secret_name(&entry.name).is_err()
                    || entry.kind.is_empty()
                    || entry.kind.len() > 100
                    || entry.kind.chars().any(char::is_control)
                {
                    return Err("frontmatter contains invalid redacted provenance".into());
                }
                provenance.insert(entry);
            }
        }
    }
    provenance.extend(additions.iter().cloned());
    let redacted = format!(
        "redacted: {}",
        serde_json::to_string(&provenance.into_iter().collect::<Vec<_>>())
            .map_err(|_| "could not encode redacted provenance")?
    );
    match redacted_index {
        Some(index) => lines[index] = redacted,
        None => lines.push(redacted),
    }
    match updated_index {
        Some(index) => lines[index] = format!("updated: {updated_at}"),
        None => lines.push(format!("updated: {updated_at}")),
    }

    let mut next = String::with_capacity(content.len() + 256);
    next.push_str(&content[..open_end]);
    for line in lines {
        next.push_str(&line);
        next.push_str(newline);
    }
    next.push_str(&content[close_start..]);
    Ok(next)
}

fn fallback_secret_name(kind: &str) -> &'static str {
    match kind {
        "AWS access key id" => "AWS_ACCESS_KEY_ID",
        "GitHub personal access token" | "GitHub fine-grained token" => "GITHUB_TOKEN",
        "GitHub app/OAuth token" => "GITHUB_APP_TOKEN",
        "Anthropic API key" => "ANTHROPIC_API_KEY",
        "OpenAI API key" => "OPENAI_API_KEY",
        "Slack token" => "SLACK_TOKEN",
        "Google API key" => "GOOGLE_API_KEY",
        "Stripe live key" => "STRIPE_KEY",
        "private key (PEM block)" => "PRIVATE_KEY",
        "1Password share link" => "ONEPASSWORD_SHARE",
        _ => "SECRET",
    }
}

fn screaming_snake(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(64));
    let mut separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !out.is_empty() {
                out.push('_');
            }
            separator = false;
            out.push(character.to_ascii_uppercase());
        } else {
            separator = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("SECRET");
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert_str(0, "SECRET_");
    }
    out.truncate(64);
    out
}

fn contextual_secret_name(content: &str, start: usize, kind: &str) -> String {
    let line_start = content[..start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let prefix = content[line_start..start]
        .trim_end()
        .trim_end_matches(['"', '\'', '`', ' ']);
    let label = prefix
        .rfind([':', '='])
        .map(|delimiter| &prefix[..delimiter])
        .and_then(|before| before.rsplit(['{', '[', ',', ';']).next().map(str::trim))
        .map(|candidate| candidate.trim_matches(['"', '\'', '`', ' ']))
        .filter(|candidate| {
            !candidate.is_empty()
                && candidate.len() <= 48
                && candidate
                    .chars()
                    .any(|character| character.is_ascii_alphabetic())
        });
    screaming_snake(label.unwrap_or_else(|| fallback_secret_name(kind)))
}

fn disambiguated_name(base: &str, hash: &str, attempt: usize) -> String {
    if attempt == 0 {
        return base.to_string();
    }
    let hash_len = (8 + (attempt - 1) * 4).min(62);
    if hash_len >= 62 {
        return format!("S_{}", &hash[..62]);
    }
    let base_len = 64usize.saturating_sub(hash_len + 1).max(1);
    format!(
        "{}_{}",
        &base[..base.len().min(base_len)],
        &hash[..hash_len]
    )
}

fn read_vault_value(cfg: &Config, brain: &str, name: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let mut response = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/vault?name={}", enc(brain), enc(name)),
            None,
            true,
        ),
        "reading an existing vault item for adopt",
    );
    let encoded = match response.get_mut("valueBase64").map(std::mem::take) {
        Some(Value::String(value)) => value,
        _ => fail("hub omitted an existing vault value during adopt", None),
    };
    let max_encoded = MAX_SECRET_VALUE_BYTES.div_ceil(3) * 4;
    if encoded.len() > max_encoded {
        fail("hub returned an oversized vault value during adopt", None);
    }
    let mut encoded = encoded.into_bytes();
    let mut decoded = STANDARD
        .decode(&encoded)
        .unwrap_or_else(|_| fail("hub returned invalid base64 during adopt", None));
    if decoded.is_empty()
        || decoded.len() > MAX_SECRET_VALUE_BYTES
        || STANDARD.encode(&decoded).as_bytes() != encoded
    {
        encoded.fill(0);
        decoded.fill(0);
        fail(
            "hub returned a non-canonical vault value during adopt",
            None,
        );
    }
    encoded.fill(0);
    decoded
}

fn commit_adopt_value(
    cfg: &Config,
    brain: &str,
    hash: &str,
    value: &[u8],
    base_name: &str,
    journal: &mut AdoptJournal,
    root: &crate::safe_path::SafeDir,
) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    for attempt in 0..=16 {
        let candidate = if attempt == 0 {
            journal
                .mappings
                .get(hash)
                .cloned()
                .unwrap_or_else(|| base_name.to_string())
        } else {
            disambiguated_name(base_name, hash, attempt)
        };
        if journal
            .mappings
            .iter()
            .any(|(other_hash, name)| other_hash != hash && name == &candidate)
        {
            continue;
        }
        if journal.mappings.get(hash) != Some(&candidate) {
            journal.mappings.insert(hash.to_string(), candidate.clone());
            write_adopt_journal(root, journal).unwrap_or_else(|error| fail(&error, None));
        }
        let response = request(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/vault", enc(brain)),
            Some(&json!({ "name": candidate, "valueBase64": STANDARD.encode(value) })),
            true,
        );
        if (200..300).contains(&response.status) {
            ensure_ok(response, "adopting a vault item");
            return candidate;
        }
        if response.status == 409 && body_code(&response) == Some("vault_item_exists") {
            let mut existing = read_vault_value(cfg, brain, &candidate);
            let existing_hash = format!("{:x}", Sha256::digest(&existing));
            existing.fill(0);
            if existing_hash == hash {
                return candidate;
            }
            continue;
        }
        ensure_ok(response, "adopting a vault item");
    }
    fail(
        "could not derive a collision-free vault name during adopt",
        None,
    )
}

fn rewritten_adopt_file(
    content: &str,
    occurrences: &[AdoptOccurrence],
    mappings: &BTreeMap<String, String>,
    updated_at: &str,
) -> Result<String, String> {
    let mut next = content.to_string();
    let mut provenance = BTreeSet::new();
    let mut ordered = occurrences.to_vec();
    ordered.sort_by_key(|occurrence| (occurrence.start, occurrence.end));
    for pair in ordered.windows(2) {
        if pair[0].end > pair[1].start {
            return Err("overlapping credential spans cannot be rewritten safely".into());
        }
    }
    for occurrence in ordered.iter().rev() {
        let Some(name) = mappings.get(&occurrence.hash) else {
            return Err("adopt journal lost a credential mapping".into());
        };
        let Some(value) = content.as_bytes().get(occurrence.start..occurrence.end) else {
            return Err("credential span moved before rewrite".into());
        };
        if format!("{:x}", Sha256::digest(value)) != occurrence.hash {
            return Err("credential bytes changed before rewrite".into());
        }
        next.replace_range(occurrence.start..occurrence.end, &format!("${name}"));
        provenance.insert(RedactedProvenance {
            name: name.clone(),
            kind: occurrence.kind.to_string(),
        });
    }
    apply_redacted_provenance(&next, &provenance, updated_at)
}

fn finish_adopt_scope(
    root_path: &Path,
    journal: &AdoptJournal,
) -> Result<(usize, Vec<String>), String> {
    let scope = local::load(root_path)?;
    let mut exact_entries = BTreeSet::new();
    for path in &journal.paths {
        exact_entries.insert(local::entry_for(path)?);
    }
    let removed = if let Some(scope) = &scope {
        let (next, removed) = local::remove_exact_entries(scope.raw(), &exact_entries);
        if removed > 0 {
            local::write(root_path, &next)?;
        }
        removed
    } else {
        0
    };
    let remaining_scope = local::load(root_path)?;
    let still_kept = journal
        .paths
        .iter()
        .filter(|path| {
            remaining_scope
                .as_ref()
                .is_some_and(|scope| scope.keeps_home(path))
        })
        .cloned()
        .collect();
    Ok((removed, still_kept))
}

pub fn secrets_adopt(cfg: &Config, dir: Option<String>) {
    if cfg.key.is_none() {
        fail(NOT_LOGGED_IN, None);
    }
    let dir = dir.unwrap_or_else(|| ".".to_string());
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    let root_path = std::fs::canonicalize(&dir)
        .unwrap_or_else(|error| fail(&format!("could not resolve store directory: {error}"), None));
    let root = crate::safe_path::SafeDir::open(&root_path).unwrap_or_else(|error| {
        fail(
            &format!("cannot securely hold store directory: {error}"),
            None,
        )
    });
    let _lock = root
        .lock_relative(PULL_LOCK_FILE)
        .unwrap_or_else(|error| fail(&format!("cannot lock store state: {error}"), None));
    if recover_pull_transaction(&root).unwrap_or_else(|error| fail(&error, None)) {
        note("recovered an interrupted pull before adopting credentials");
    }
    let baseline = load_sync_baseline(&root_path)
        .unwrap_or_else(|error| fail(&error, None))
        .unwrap_or_else(|| {
            fail(
                &format!(
                    "{dir} has no {SYNC_BASELINE_FILE}; clone or push the brain once before `sevra secrets adopt` so the vault destination is unambiguous"
                ),
                None,
            )
        });
    let mut journal = load_adopt_journal(&root)
        .unwrap_or_else(|error| fail(&error, None))
        .unwrap_or_else(|| AdoptJournal {
            version: 1,
            brain_id: baseline.brain_id.clone(),
            mappings: BTreeMap::new(),
            paths: BTreeSet::new(),
        });
    if journal.brain_id != baseline.brain_id {
        fail(
            &format!(
                "{ADOPT_JOURNAL_FILE} belongs to a different brain; refusing to move credentials"
            ),
            None,
        );
    }
    if journal.mappings.values().collect::<BTreeSet<_>>().len() != journal.mappings.len() {
        fail(
            &format!("{ADOPT_JOURNAL_FILE} maps different values to the same vault name"),
            None,
        );
    }

    let scope = local::load(&root_path).unwrap_or_else(|error| fail(&error, None));
    let (store, _) = read_store_checked(&dir, false);
    let mut asset_scan = crate::assets::scan_declared_asset_secrets(
        &dir,
        store.assets.as_deref(),
        scope.as_ref(),
        true,
    );
    if let Some(message) = asset_scan.coverage_note() {
        note(&message);
    }
    let store_hits = scan_store(&store);
    let mut unsupported: Vec<SecretHit> = store_hits
        .into_iter()
        .filter(|hit| hit.in_path || hit.store_path == "assets.jsonl")
        .collect();
    unsupported.append(&mut asset_scan.hits);
    if !unsupported.is_empty() {
        let mut message = format!(
            "adopt refused before vault access: {} match(es) are outside editable markdown content:",
            unsupported.len()
        );
        message.push_str(&secret_hits_block(&unsupported));
        message.push_str(
            "\nasset bytes are content-addressed and filenames are identity; keep the file home with `sevra secrets quarantine`, or rename/edit it deliberately",
        );
        fail(&message, Some(secret_hits_data(&unsupported)));
    }

    let mut originals = BTreeMap::new();
    let mut by_path: BTreeMap<String, Vec<AdoptOccurrence>> = BTreeMap::new();
    let mut values: BTreeMap<String, AdoptValue> = BTreeMap::new();
    let updated_at = utc_rfc3339_now();
    for file in &store.files {
        let spans = crate::scan::content_secret_spans(&file.content).unwrap_or_else(|error| {
            fail(
                &format!(
                    "cannot adopt {} safely: {error}",
                    terminal_safe(&redact_path(&file.path))
                ),
                None,
            )
        });
        if spans.is_empty() {
            continue;
        }
        // Validate the frontmatter shape for every file before the first vault
        // request. A later local failure may leave an unused vault item, but
        // can never leave a literal removed without its durable value.
        apply_redacted_provenance(&file.content, &BTreeSet::new(), &updated_at).unwrap_or_else(
            |error| {
                fail(
                    &format!(
                        "cannot record redaction provenance in {}: {error}",
                        terminal_safe(&file.path)
                    ),
                    None,
                )
            },
        );
        originals.insert(file.path.clone(), file.content.clone());
        for span in spans {
            let bytes = file.content.as_bytes()[span.start..span.end].to_vec();
            if bytes.len() > MAX_SECRET_VALUE_BYTES {
                fail(
                    &format!(
                        "cannot adopt {} in {}: the matched value is {} bytes, above the {MAX_SECRET_VALUE_BYTES}-byte vault item limit",
                        span.kind,
                        terminal_safe(&file.path),
                        bytes.len()
                    ),
                    None,
                );
            }
            let hash = format!("{:x}", Sha256::digest(&bytes));
            let occurrence = AdoptOccurrence {
                hash: hash.clone(),
                start: span.start,
                end: span.end,
                line: file.content[..span.start]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count()
                    + 1,
                kind: span.kind,
            };
            by_path
                .entry(file.path.clone())
                .or_default()
                .push(occurrence.clone());
            let entry = values.entry(hash.clone()).or_insert_with(|| AdoptValue {
                bytes: bytes.clone(),
                base_name: contextual_secret_name(&file.content, span.start, span.kind),
            });
            if entry.bytes != bytes {
                fail("SHA-256 collision while grouping credentials", None);
            }
        }
    }

    if values.len() > 256 {
        fail(
            &format!(
                "adopt found {} distinct values; one brain vault holds at most 256 items",
                values.len()
            ),
            None,
        );
    }

    for path in by_path.keys() {
        journal.paths.insert(path.clone());
        if path.starts_with("sources/") {
            note(&format!(
                "warning: adopt will edit immutable evidence {} after its vault values are durable; redacted provenance will record every replacement",
                terminal_safe(path)
            ));
        }
    }
    if journal.paths.len() > MAX_STORE_FILES {
        fail(
            &format!("{ADOPT_JOURNAL_FILE} would exceed the store path limit"),
            None,
        );
    }
    for (hash, value) in &values {
        if journal.mappings.contains_key(hash) {
            continue;
        }
        let mut assigned = false;
        for attempt in 0..=16 {
            let candidate = disambiguated_name(&value.base_name, hash, attempt);
            if !journal.mappings.values().any(|name| name == &candidate) {
                journal.mappings.insert(hash.clone(), candidate);
                assigned = true;
                break;
            }
        }
        if !assigned {
            fail(
                "could not derive a collision-free vault name from the adopt journal",
                None,
            );
        }
    }
    if !values.is_empty() || !journal.paths.is_empty() {
        write_adopt_journal(&root, &journal).unwrap_or_else(|error| fail(&error, None));
    }

    for (hash, value) in &mut values {
        let final_name = commit_adopt_value(
            cfg,
            &baseline.brain_id,
            hash,
            &value.bytes,
            &value.base_name,
            &mut journal,
            &root,
        );
        value.bytes.fill(0);
        debug_assert_eq!(journal.mappings.get(hash), Some(&final_name));
    }

    if cfg!(debug_assertions)
        && std::env::var("SEVRA_TEST_ADOPT_EXIT_AFTER_VAULT").as_deref() == Ok("1")
    {
        std::process::exit(86);
    }

    let mut rewrites: BTreeMap<String, (String, std::fs::Permissions)> = BTreeMap::new();
    for (path, occurrences) in &by_path {
        let Some((bytes, permissions, _)) =
            held_file_state(&root, path).unwrap_or_else(|error| fail(&error, None))
        else {
            fail(
                &format!(
                    "adopt source disappeared before rewrite: {}",
                    terminal_safe(path)
                ),
                None,
            )
        };
        let original = originals.get(path).expect("affected path has source text");
        if bytes != original.as_bytes() {
            fail(
                &format!(
                    "adopt stopped because {} changed after scanning; no stale bytes were overwritten (rerun to resume)",
                    terminal_safe(path)
                ),
                None,
            );
        }
        let next = rewritten_adopt_file(original, occurrences, &journal.mappings, &updated_at)
            .unwrap_or_else(|error| {
                fail(
                    &format!("cannot rewrite {}: {error}", terminal_safe(path)),
                    None,
                )
            });
        rewrites.insert(path.clone(), (next, permissions));
    }

    let mut rewritten = Vec::new();
    let mut replacement_count = 0usize;
    for (path, (next, permissions)) in &rewrites {
        root.atomic_write(path, next.as_bytes(), false, export_mode(permissions))
            .unwrap_or_else(|error| {
                fail(
                    &format!(
                        "could not securely rewrite {} after vault commit: {error}; rerun to resume",
                        terminal_safe(path)
                    ),
                    None,
                )
            });
        root.restore_permissions(path, export_mode(permissions), permissions.readonly())
            .unwrap_or_else(|error| {
                fail(
                    &format!(
                        "rewrote {} but could not restore its permissions: {error}",
                        terminal_safe(path)
                    ),
                    None,
                )
            });
        replacement_count += by_path[path].len();
        rewritten.push(path.clone());
        if cfg!(debug_assertions)
            && rewritten.len() == 1
            && std::env::var("SEVRA_TEST_ADOPT_EXIT_AFTER_FILE").as_deref() == Ok("1")
        {
            std::process::exit(87);
        }
    }

    let (unquarantined, still_kept) =
        finish_adopt_scope(&root_path, &journal).unwrap_or_else(|error| {
            fail(
                &format!("adopted values but {error}; rerun to resume"),
                None,
            )
        });
    root.remove_regular(ADOPT_JOURNAL_FILE)
        .unwrap_or_else(|error| {
            fail(
                &format!("could not remove {ADOPT_JOURNAL_FILE}: {error}"),
                None,
            )
        });

    let mut human = if replacement_count == 0 {
        "no adoptable markdown credentials remain".to_string()
    } else {
        format!(
            "adopted {} distinct vault item(s); replaced {replacement_count} literal(s) across {} markdown file(s):",
            values.len(),
            rewritten.len()
        )
    };
    for path in &rewritten {
        human.push_str(&format!("\n  {}", terminal_safe(path)));
        for occurrence in &by_path[path] {
            let name = &journal.mappings[&occurrence.hash];
            human.push_str(&format!(
                "\n    line {}: [credential] -> ${}",
                occurrence.line,
                terminal_safe(name)
            ));
        }
    }
    if unquarantined > 0 {
        human.push_str(&format!(
            "\nunquarantined {unquarantined} exact .sevralocal entr{} after redaction",
            if unquarantined == 1 { "y" } else { "ies" }
        ));
    }
    if !still_kept.is_empty() {
        human.push_str(
            "\nwarning: these clean files are still covered by a broader .sevralocal glob; review that glob before push:",
        );
        for path in &still_kept {
            human.push_str(&format!("\n  {}", terminal_safe(path)));
        }
    }
    out_layout(
        &human,
        Some(json!({
            "brain": baseline.brain_id,
            "vaultItems": journal.mappings.values().collect::<Vec<_>>(),
            "distinctValues": values.len(),
            "replacements": replacement_count,
            "files": rewritten,
            "unquarantinedEntries": unquarantined,
            "stillKeptHome": still_kept,
            "journalRemoved": true,
        })),
    );
}

// --- secrets scan / quarantine (the local store, no hub) -----------------------
//
// The other half of the vault story: secrets that are FILES in the store.
// `scan` is push's secret gate as a read-only report; `quarantine` gives the
// third exit — keep the files home in `.sevralocal` instead of shipping or
// editing them. Both are offline and need no credential. The one file sevra
// ever edits is `.sevralocal`, and only by appending.

/// The forward-only truth, stated on every quarantine run.
const FORWARD_ONLY_NOTE: &str = "kept-home is forward-only — marking changes future snapshots and erases nothing by itself. Files already pushed remain in retained packs; a kept-home asset remains declared, so its blob is not swept; retention-locked backups persist for about 31 days. Rotate at the issuer immediately. Byte erasure requires `sevra delete`, completion of the sweep and backup-retention window, then a fresh push";

/// `secrets scan [dir]` — the push secret scan, read-only: report what a
/// push of <dir> would refuse on, in exactly the push-refusal shape. Exit 1
/// on matches, 0 on a clean store; matched values are never shown. Honors
/// `.sevralocal`: kept-home files never ride, so they are not scanned here
/// (quarantine's full view is the one that sees them).
pub fn secrets_scan(dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| ".".into());
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    let (store, stats) = read_store_checked(&dir, true);
    if stats.kept_home > 0 {
        note(&format!(
            "{} file(s) kept home (.sevralocal) — not scanned; they never ride a push",
            stats.kept_home
        ));
    }
    let scope = local::load(Path::new(&dir)).unwrap_or_else(|msg| fail(&msg, None));
    let mut asset_scan = crate::assets::scan_declared_asset_secrets(
        &dir,
        store.assets.as_deref(),
        scope.as_ref(),
        false,
    );
    if let Some(message) = asset_scan.coverage_note() {
        note(&message);
    }
    let mut hits = scan_store(&store);
    hits.append(&mut asset_scan.hits);
    if hits.is_empty() {
        out(
            &format!(
                "no matches for known secret formats across {} file(s)",
                stats.files
            ),
            Some(json!({
                "secretHits": [],
                "total": 0,
                "assetSecretScan": asset_scan.to_json(),
            })),
        );
        return;
    }
    let mut msg = format!(
        "{} match(es) for known secret formats in the store (matched values are never shown):",
        hits.len()
    );
    msg.push_str(&secret_hits_block(&hits));
    msg.push_str(&format!(
        "\nrotate anything that ever lived here; keep live secrets in a password manager and references to them in the brain.\n{EXISTING_BYTES_REMEDIATION}\nmove markdown literals into the brain vault: `sevra secrets adopt {dir}`. Quarantine only when the whole file is secret or an asset: `sevra secrets quarantine {dir}`. Or edit deliberately"
    ));
    let mut data = secret_hits_data(&hits);
    if let Some(object) = data.as_object_mut() {
        object.insert("assetSecretScan".into(), asset_scan.to_json());
    }
    fail(&msg, Some(data));
}

/// `secrets quarantine [dir]` — keep secret-bearing files home: scan the
/// FULL store (kept-home files included — that is what `alreadyCovered`
/// counts) and append each hit file's exact path to `.sevralocal`, creating
/// it when absent. Idempotent; `--dry-run` previews; `--closure` also marks
/// the files connected to a marked one through wiki-links (via `dbmd emit`).
/// `DB.md` and `assets.jsonl` are never marked — they ride every push, so a
/// secret inside them stays an edit case (warned, not acted on).
pub fn secrets_quarantine(dir: Option<String>, dry_run: bool, closure: bool) {
    let dir = dir.unwrap_or_else(|| ".".into());
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    // Load the scope directly (not through the walk): quarantine needs the
    // verbatim text to preserve, and a structurally invalid `.sevralocal`
    // refuses here exactly as push refuses.
    let scope = local::load(Path::new(&dir)).unwrap_or_else(|msg| fail(&msg, None));
    let covered = |p: &str| scope.as_ref().is_some_and(|s| s.keeps_home(p));
    let (store, _stats) = read_store_checked(&dir, false);
    let mut asset_scan = crate::assets::scan_declared_asset_secrets(
        &dir,
        store.assets.as_deref(),
        scope.as_ref(),
        true,
    );
    if let Some(message) = asset_scan.coverage_note() {
        note(&message);
    }
    let mut hits = scan_store(&store);
    hits.append(&mut asset_scan.hits);

    // Unique hit files: exact path → shown (redacted) spelling.
    let mut hit_files: BTreeMap<String, String> = BTreeMap::new();
    for hit in &hits {
        hit_files
            .entry(hit.store_path.clone())
            .or_insert_with(|| hit.path.clone());
    }
    let mut warnings: Vec<(&'static str, String)> = Vec::new();
    // Warning: the filename itself is the secret. Reported per file, never
    // acted on — renaming is the operator's move (and the path is already
    // shown redacted by the scanner).
    let in_path_files: BTreeSet<&String> = hits
        .iter()
        .filter(|h| h.in_path)
        .map(|h| &h.store_path)
        .collect();
    for exact in &in_path_files {
        warnings.push(("filename_secret", hit_files[*exact].clone()));
    }

    let mut marked: Vec<(String, String)> = Vec::new(); // (exact, shown)
    let mut already_covered = 0usize;
    for (exact, shown) in &hit_files {
        if local::MUST_RIDE.contains(&exact.as_str()) {
            warnings.push(("must_ride", shown.clone()));
        } else if covered(exact) {
            already_covered += 1;
        } else {
            marked.push((exact.clone(), shown.clone()));
        }
    }

    // --closure: computed BEFORE any write — a missing dbmd fails up front.
    // The dump is kept: the link blast-radius report below needs the same one,
    // and a whole-store emit is a SWEEP (seconds on a 30k-file store).
    let mut emit_dump: Option<Value> = None;
    let closure_marked: Vec<String> = if closure {
        let emit = run_dbmd_emit(&dir);
        let seeds: BTreeSet<String> = marked.iter().map(|(exact, _)| exact.clone()).collect();
        let component = closure_component(&emit, &seeds)
            .into_iter()
            .filter(|p| {
                !seeds.contains(p) && !covered(p) && !local::MUST_RIDE.contains(&p.as_str())
            })
            .collect(); // BTreeSet iteration: already sorted
        emit_dump = Some(emit);
        component
    } else {
        Vec::new()
    };

    // The LINK blast radius of what is about to be kept home. Advisory: a
    // missing dbmd simply means no report, never a refused quarantine.
    let newly_marked: BTreeSet<String> = marked
        .iter()
        .map(|(exact, _)| exact.clone())
        .chain(closure_marked.iter().cloned())
        .collect();
    let dangling: Vec<(String, usize)> = if newly_marked.is_empty() {
        Vec::new()
    } else {
        match emit_dump.take().or_else(|| try_dbmd_emit(&dir)) {
            Some(emit) => incoming_link_counts(&emit, &newly_marked),
            None => Vec::new(),
        }
    };
    let dangling_total: usize = dangling.iter().map(|(_, n)| n).sum();

    // Warning: the asset manifest rides every push and still names kept-home
    // files (existing entries and this run's marks alike). Read-only over
    // the JSONL; malformed lines are tolerated silently.
    if let Some(assets) = store.assets.as_deref() {
        let mut named: BTreeSet<String> = BTreeSet::new();
        for line in assets.lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(p) = v.get("path").and_then(Value::as_str) else {
                continue;
            };
            let kept = covered(p)
                || marked.iter().any(|(exact, _)| exact == p)
                || closure_marked.iter().any(|exact| exact == p);
            if kept {
                named.insert(p.to_string());
            }
        }
        for p in named {
            warnings.push(("manifest_names_kept_home", redact_path(&p)));
        }
    }
    warnings.sort();

    // The write — the only file sevra ever edits, append-only. Exact paths
    // (escaped where a filename carries glob metacharacters), sorted.
    let mut new_entries: Vec<String> = marked
        .iter()
        .map(|(exact, _)| local::entry_for(exact))
        .chain(closure_marked.iter().map(|exact| local::entry_for(exact)))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| fail(&e, None));
    new_entries.sort();
    if !dry_run && !new_entries.is_empty() {
        let raw = scope.as_ref().map(|s| s.raw()).unwrap_or("");
        let body = local::append_entries(raw, &new_entries);
        let root = std::fs::canonicalize(&dir)
            .unwrap_or_else(|e| fail(&format!("could not resolve store directory: {e}"), None));
        local::write(&root, &body).unwrap_or_else(|e| fail(&e, None));
    }

    // Report. Shown spellings only (redacted wherever a path matched).
    let mut marked_shown: Vec<String> = marked.iter().map(|(_, shown)| shown.clone()).collect();
    marked_shown.sort();
    let closure_shown: Vec<String> = closure_marked.iter().map(|p| redact_path(p)).collect();
    let mut human = if hits.is_empty() {
        "no matches for known secret formats — nothing to keep home".to_string()
    } else if marked.is_empty() {
        "nothing new to mark".to_string()
    } else {
        let verb = if dry_run {
            "would keep home"
        } else {
            "kept home"
        };
        let mut s = format!("{verb} (.sevralocal): {} file(s)", marked_shown.len());
        for shown in &marked_shown {
            s.push_str(&format!("\n  {}", terminal_safe(shown)));
        }
        s
    };
    if !closure_shown.is_empty() {
        let verb = if dry_run { "would add" } else { "added" };
        human.push_str(&format!(
            "\nclosure {verb} {} linked file(s):",
            closure_shown.len()
        ));
        for shown in &closure_shown {
            human.push_str(&format!("\n  {}", terminal_safe(shown)));
        }
    }
    if already_covered > 0 {
        human.push_str(&format!(
            "\n{already_covered} hit file(s) already covered by .sevralocal"
        ));
    }
    // What keeping these home costs the HOSTED graph. Locally nothing changes
    // (the files stay, dbmd resolves every link); on the hub each of these
    // links dangles, and the push summary's broken-edge count is this number.
    if dangling_total > 0 {
        let verb = if dry_run {
            "would dangle"
        } else {
            "now dangle"
        };
        human.push_str(&format!(
            "\nlinks: {dangling_total} incoming link(s) {verb} in the HOSTED copy (locally nothing changes):"
        ));
        for (path, n) in dangling.iter().take(5) {
            human.push_str(&format!("\n  {n} → {}", terminal_safe(&redact_path(path))));
        }
        if dangling.len() > 5 {
            human.push_str(&format!("\n  … and {} more file(s)", dangling.len() - 5));
        }
        human.push_str(
            "\nto keep the graph whole instead: rotate the credential at its issuer, redact the file, and un-mark it",
        );
    }
    for (kind, path) in &warnings {
        let path = terminal_safe(path);
        let line = match *kind {
            "filename_secret" => format!(
                "warning: {path} — the filename itself is the secret — consider renaming; a future feed removal would record the name"
            ),
            "must_ride" => format!(
                "warning: {path} carries a match but rides every push (store config / asset manifest) — never marked; edit it, the scanner keeps flagging it"
            ),
            _ => format!(
                "warning: assets.jsonl names {path} under a kept-home entry — the manifest rides and carries these names; removing entries is your deliberate edit"
            ),
        };
        human.push_str(&format!("\n{line}"));
    }
    if !json_mode() {
        note(FORWARD_ONLY_NOTE);
    }
    out_layout(
        &human,
        Some(json!({
            "marked": marked_shown,
            "closureMarked": closure_shown,
            "alreadyCovered": already_covered,
            "danglingLinks": dangling_total,
            "danglingByPath": dangling
                .iter()
                .map(|(p, n)| json!({ "path": redact_path(p), "incoming": n }))
                .collect::<Vec<_>>(),
            "warnings": warnings
                .iter()
                .map(|(kind, path)| json!({ "kind": kind, "path": path }))
                .collect::<Vec<_>>(),
            "total": hits.len(),
            "assetSecretScan": asset_scan.to_json(),
            "note": FORWARD_ONLY_NOTE,
        })),
    );
}

/// `--closure`'s graph source: `dbmd emit --json` run in the store. A
/// missing dbmd fails up front — before anything is written — with the
/// install hint; so does a failed or unparseable emit. Third-party error
/// text passes through the secret redactor before it is shown.
/// The soft form: `None` whenever dbmd is absent, fails, or answers
/// unparseably. Used by the link blast-radius report, which is ADVISORY —
/// keeping a secret home must never depend on a second tool being installed.
fn try_dbmd_emit(dir: &str) -> Option<Value> {
    let output = Command::new("dbmd")
        .args(["emit", "--json"])
        .current_dir(dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

fn run_dbmd_emit_for(dir: &str, purpose: &str) -> Value {
    let output = match Command::new("dbmd")
        .args(["emit", "--json"])
        .current_dir(dir)
        .output()
    {
        Ok(o) => o,
        Err(e) => fail(
            &format!(
                "{purpose} needs dbmd and it could not run (is it installed? https://www.sevrahq.com/install): {e}"
            ),
            None,
        ),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first: String = stderr
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        fail(
            &format!(
                "{purpose}: `dbmd emit` failed in {dir}: {}",
                redact_path(first.trim())
            ),
            None,
        );
    }
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        fail(
            &format!("{purpose}: `dbmd emit --json` produced unparseable output: {e}"),
            None,
        )
    })
}

fn run_dbmd_emit(dir: &str) -> Value {
    run_dbmd_emit_for(dir, "--closure")
}

/// The undirected reachability component of `seeds` over the content graph
/// `dbmd emit --json` describes (`files[].links`; targets arrive normalized
/// with `.md` appended). Nodes are the emitted files MINUS the root `DB.md`:
/// emit does include the store config, but it links broadly and must never
/// bridge otherwise-unconnected components (derived catalogs and the log are
/// already absent from emit, so over-marking through them cannot happen
/// either). An edge exists only between two emitted files — a dangling
/// target is nobody's bridge. Returns the component, seeds included.
/// Incoming wiki-links to each kept-home path — the LINK blast radius, which
/// is not the secret blast radius `--closure` computes. Keeping a file home is
/// forward-safe for secrets and lossy for the graph: the file stays in the
/// local brain, so `dbmd` still resolves every link, but the hosted copy never
/// receives it and each incoming link dangles there.
///
/// Dogfooded into existence (2026-07-30): quarantining a raw Workflowy export
/// that 11,587 records name as their `source:` dangled 11,590 edges in the
/// hosted brain — 16% of its graph — reported only as a number in the push
/// summary, with nothing connecting it to the quarantine that caused it.
/// Counting is dbmd's own `links` projection (same normalization, one process),
/// so this never becomes a second implementation of link resolution.
///
/// Returns (path, incoming-link count) for marked paths that ANYTHING links to,
/// heaviest first.
fn incoming_link_counts(emit: &Value, marked: &BTreeSet<String>) -> Vec<(String, usize)> {
    let files = emit
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &files {
        let Some(src) = f.get("path").and_then(Value::as_str) else {
            continue;
        };
        for link in f
            .get("links")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(t) = link.as_str() else { continue };
            // A file's link to itself does not dangle when it leaves together
            // with its own text.
            if t == src {
                continue;
            }
            if let Some(hit) = marked.get(t) {
                *counts.entry(hit.as_str()).or_default() += 1;
            }
        }
    }
    let mut out: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(p, n)| (p.to_string(), n))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

fn closure_component(emit: &Value, seeds: &BTreeSet<String>) -> BTreeSet<String> {
    let files = emit
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let nodes: BTreeSet<&str> = files
        .iter()
        .filter_map(|f| f.get("path").and_then(Value::as_str))
        .filter(|p| *p != "DB.md")
        .collect();
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for f in &files {
        let Some(p) = f.get("path").and_then(Value::as_str) else {
            continue;
        };
        if p == "DB.md" {
            continue;
        }
        for link in f
            .get("links")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(t) = link.as_str() else { continue };
            if t != p && nodes.contains(t) {
                adj.entry(p).or_default().push(t);
                adj.entry(t).or_default().push(p);
            }
        }
    }
    let mut component: BTreeSet<String> = seeds.clone();
    let mut queue: VecDeque<&str> = nodes
        .iter()
        .copied()
        .filter(|n| seeds.contains(*n))
        .collect();
    while let Some(n) = queue.pop_front() {
        for next in adj.get(n).into_iter().flatten().copied() {
            if component.insert(next.to_string()) {
                queue.push_back(next);
            }
        }
    }
    component
}

// --- validate (shells dbmd) --------------------------------------------------

pub fn validate(dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| ".".into());
    // is_dir, not exists: handing dbmd a FILE as its working dir would fail
    // with a spawn error that misreads as "dbmd is not installed".
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    // The --json contract holds THROUGH the shell-out: dbmd has its own
    // global --json, so machine mode forwards it.
    let mut args = vec!["validate", "--all"];
    if json_mode() {
        args.push("--json");
    }
    match Command::new("dbmd").args(&args).current_dir(&dir).status() {
        Ok(status) => {
            // A signal death (no code) is not a pass.
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => fail(
            &format!("could not run dbmd (is it installed? https://www.sevrahq.com/install): {e}"),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contained_rejects_escapes() {
        let root = Path::new("/safe/root");
        assert!(contained(root, "notes/a.md").is_some());
        assert!(contained(root, "a.md").is_some());
        assert!(contained(root, "../a.md").is_none());
        assert!(contained(root, "notes/../../a.md").is_none());
        assert!(contained(root, "/etc/passwd").is_none());
        assert!(contained(root, "").is_none());
        assert!(contained(root, "a\0b").is_none());
        assert!(contained(root, "./a.md").is_none()); // hub paths are normalized; `./` is refused
    }

    fn manifest(paths: &[&str]) -> Vec<(String, Vec<u8>)> {
        paths
            .iter()
            .map(|path| ((*path).to_string(), Vec::new()))
            .collect()
    }

    #[test]
    fn portable_export_manifest_rejects_every_alias_class() {
        for paths in [
            vec!["a", "a/b"],
            vec!["a/b", "a"],
            vec!["A.md", "a.md"],
            vec!["Folder/a.md", "folder/b.md"],
            vec!["é.md", "e\u{301}.md"],
        ] {
            assert!(
                validate_export_manifest(&manifest(&paths)).is_err(),
                "must reject {paths:?}"
            );
        }
        for path in [
            "name.",
            "name ",
            "CON",
            "con.md",
            "PRN.txt",
            "COM1.log",
            "COM¹.log",
            "lpt³",
            "lpt9",
            "stream:secret",
            "dir\\file",
            "bad?.md",
            "bad\u{1b}.md",
        ] {
            assert!(
                validate_export_manifest(&manifest(&[path])).is_err(),
                "must reject {path:?}"
            );
        }
        let oversized_component = "a".repeat(256);
        assert!(validate_export_manifest(&manifest(&[&oversized_component])).is_err());
        let normalization_expansion = "é".repeat(100);
        assert!(validate_export_manifest(&manifest(&[&normalization_expansion])).is_err());
        let oversized_path = std::iter::repeat_n("segment", 130)
            .collect::<Vec<_>>()
            .join("/");
        assert!(validate_export_manifest(&manifest(&[&oversized_path])).is_err());
        validate_export_manifest(&manifest(&["DB.md", "records/a.md", "records/b.md"]))
            .expect("ordinary portable manifest");
    }

    #[test]
    fn portable_core_paths_require_canonical_controls_and_exclude_internal_state() {
        for path in [
            "Db.md",
            "Assets.jsonl",
            ".SevraLocal",
            "feed/x",
            "Blobs/x",
            "packs/x",
            "pub/x",
            "meta/x",
        ] {
            assert!(
                validate_portable_core_path(path).is_err(),
                "{path} must not be hosted or exported"
            );
        }
        validate_portable_core_path("DB.md").unwrap();
        validate_portable_core_path("assets.jsonl").unwrap();
        validate_portable_core_path("records/a.md").unwrap();
    }

    #[test]
    fn destination_type_failure_is_preflighted_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("out");
        std::fs::create_dir_all(root.join("later")).unwrap();
        std::fs::write(root.join("first.md"), b"OLD").unwrap();
        std::fs::create_dir(root.join("later/not-a-file.md")).unwrap();
        let entries = vec![
            ("first.md".to_string(), b"NEW".to_vec()),
            ("later/not-a-file.md".to_string(), b"NEW".to_vec()),
        ];
        let error = preflight_export_destinations(&root, &entries).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        assert_eq!(std::fs::read(root.join("first.md")).unwrap(), b"OLD");
    }

    #[test]
    fn runtime_export_failure_rolls_back_every_attempted_destination() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root.join("first.md"), b"OLD").unwrap();
        let entries = vec![
            ("first.md".to_string(), b"NEW-ONE".to_vec()),
            ("second.md".to_string(), b"NEW-TWO".to_vec()),
        ];
        let mut writes = 0usize;
        let error = install_export_entries_with(&root, &entries, |root, path, content| {
            writes += 1;
            crate::safe_path::atomic_write(root, path, content, true, 0o600)?;
            if writes == 2 {
                return Err(std::io::Error::other("injected post-install failure"));
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains("rolled back"), "{error}");
        assert_eq!(std::fs::read(root.join("first.md")).unwrap(), b"OLD");
        assert!(
            !root.join("second.md").exists(),
            "the failing write was removed too"
        );
    }

    #[test]
    fn held_export_rollback_restores_original_identity_and_created_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap().join("out");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(root_path.join("existing.md"), b"OLD").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                root_path.join("existing.md"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let paths = vec!["existing.md".into(), "new/deep/file.md".into()];
        let mut backups = snapshot_held_destinations(&held, &paths).unwrap();

        held.atomic_write("existing.md", b"NEW", true, 0o600)
            .unwrap();
        backups[0].installed = Some(
            capture_installed_state(&held, "existing.md", Sha256::digest(b"NEW").into()).unwrap(),
        );
        held.atomic_write("new/deep/file.md", b"NEW", true, 0o600)
            .unwrap();
        backups[1].installed = Some(
            capture_installed_state(&held, "new/deep/file.md", Sha256::digest(b"NEW").into())
                .unwrap(),
        );
        rollback_held_export(&held, &backups, &["new".into(), "new/deep".into()]).unwrap();
        assert_eq!(
            std::fs::read(root_path.join("existing.md")).unwrap(),
            b"OLD"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root_path.join("existing.md"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644,
                "rollback restores the original mode, not the writer default"
            );
        }
        assert!(!root_path.join("new").exists());
    }

    #[test]
    fn held_pull_rollback_restores_a_removed_riding_path() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root_path.join("removed.md"), b"ORIGINAL").unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let mut backups = snapshot_held_destinations(&held, &["removed.md".to_string()]).unwrap();
        assert!(held.remove_regular("removed.md").unwrap());
        backups[0].installed = Some(InstalledState::Missing);

        rollback_held_export(&held, &backups, &[]).unwrap();
        assert_eq!(
            std::fs::read(root_path.join("removed.md")).unwrap(),
            b"ORIGINAL"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sync_baseline_loader_never_follows_a_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let outside = root.join("outside.json");
        std::fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join(SYNC_BASELINE_FILE)).unwrap();

        let error = load_sync_baseline(&root).unwrap_err();
        assert!(error.contains("securely open"), "{error}");
        assert_eq!(std::fs::read(outside).unwrap(), b"secret");
    }

    #[test]
    fn held_export_rollback_refuses_to_clobber_a_concurrent_edit() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root_path.join("existing.md"), b"OLD").unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let mut backups = snapshot_held_destinations(&held, &["existing.md".to_string()]).unwrap();
        held.atomic_write("existing.md", b"EXPORTED", true, 0o600)
            .unwrap();
        backups[0].installed = Some(
            capture_installed_state(&held, "existing.md", Sha256::digest(b"EXPORTED").into())
                .unwrap(),
        );
        held.atomic_write("existing.md", b"CONCURRENT", true, 0o600)
            .unwrap();

        let error = rollback_held_export(&held, &backups, &[]).unwrap_err();
        assert!(error.contains("concurrent edit"), "{error}");
        assert_eq!(
            std::fs::read(root_path.join("existing.md")).unwrap(),
            b"CONCURRENT"
        );
    }

    #[test]
    fn durable_pull_recovery_preflights_every_path_before_restoring_any() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root_path.join("a.md"), b"OLD-A").unwrap();
        std::fs::write(root_path.join("b.md"), b"OLD-B").unwrap();
        std::fs::write(root_path.join(SYNC_BASELINE_FILE), b"OLD-BASELINE").unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let paths = vec![
            "a.md".to_string(),
            "b.md".to_string(),
            SYNC_BASELINE_FILE.to_string(),
        ];
        let backups = snapshot_held_destinations(&held, &paths).unwrap();
        let next = vec![
            Some(format!("{:x}", Sha256::digest(b"NEW-A"))),
            Some(format!("{:x}", Sha256::digest(b"NEW-B"))),
            Some(format!("{:x}", Sha256::digest(b"NEW-BASELINE"))),
        ];
        prepare_pull_transaction(&held, &backups, &next, Vec::new()).unwrap();
        held.atomic_write("a.md", b"NEW-A", false, 0o600).unwrap();
        held.atomic_write("b.md", b"POST-CRASH-LOCAL-EDIT", false, 0o600)
            .unwrap();

        let error = recover_pull_transaction(&held).unwrap_err();
        assert!(error.contains("b.md changed afterward"), "{error}");
        assert_eq!(
            std::fs::read(root_path.join("a.md")).unwrap(),
            b"NEW-A",
            "recovery validates the complete namespace before restoring a.md"
        );
        assert_eq!(
            std::fs::read(root_path.join("b.md")).unwrap(),
            b"POST-CRASH-LOCAL-EDIT",
            "recovery never clobbers a post-crash edit"
        );
        assert!(root_path.join(PULL_JOURNAL_FILE).exists());
    }

    #[test]
    fn durable_pull_recovery_removes_only_exact_internal_atomic_stages() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root_path.join(SYNC_BASELINE_FILE), b"OLD-BASELINE").unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let paths = vec!["records/new.md".to_string(), SYNC_BASELINE_FILE.to_string()];
        let backups = snapshot_held_destinations(&held, &paths).unwrap();
        let next = vec![
            Some(format!("{:x}", Sha256::digest(b"NEW"))),
            Some(format!("{:x}", Sha256::digest(b"NEW-BASELINE"))),
        ];
        let journal =
            prepare_pull_transaction(&held, &backups, &next, vec!["records".to_string()]).unwrap();

        std::fs::create_dir(root_path.join("records")).unwrap();
        let exact = format!(".sevra-new-{}", "a".repeat(32));
        std::fs::write(
            root_path.join("records").join(&exact),
            b"partial staged bytes",
        )
        .unwrap();
        std::fs::write(root_path.join(&exact), b"partial journal bytes").unwrap();
        std::fs::write(root_path.join(".sevra-new-not-an-internal-stage"), b"keep").unwrap();
        std::fs::write(
            root_path.join(&journal.backup_dir).join(&exact),
            b"partial backup bytes",
        )
        .unwrap();

        assert!(recover_pull_transaction(&held).unwrap());
        assert!(!root_path.join("records").exists());
        assert!(!root_path.join(&exact).exists());
        assert_eq!(
            std::fs::read(root_path.join(".sevra-new-not-an-internal-stage")).unwrap(),
            b"keep"
        );
        assert!(!root_path.join(PULL_JOURNAL_FILE).exists());
        assert!(!root_path.join(&journal.backup_dir).exists());
    }

    #[test]
    fn atomic_stage_cleanup_without_a_journal_removes_an_exact_orphan() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let exact_file = format!(".sevra-new-{}", "b".repeat(32));
        std::fs::write(root_path.join(&exact_file), b"orphan").unwrap();

        assert!(!recover_pull_transaction(&held).unwrap());
        assert!(!root_path.join(exact_file).exists());
    }

    #[test]
    fn atomic_stage_cleanup_refuses_a_non_file_plant() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let exact_directory = format!(".sevra-new-{}", "c".repeat(32));
        std::fs::create_dir(root_path.join(&exact_directory)).unwrap();

        let error = recover_pull_transaction(&held).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        assert!(root_path.join(exact_directory).is_dir());
    }

    #[test]
    fn durable_pull_recovery_keeps_a_transaction_whose_baseline_committed() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root_path.join("a.md"), b"OLD-A").unwrap();
        std::fs::write(root_path.join(SYNC_BASELINE_FILE), b"OLD-BASELINE").unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let paths = vec!["a.md".to_string(), SYNC_BASELINE_FILE.to_string()];
        let backups = snapshot_held_destinations(&held, &paths).unwrap();
        let next = vec![
            Some(format!("{:x}", Sha256::digest(b"NEW-A"))),
            Some(format!("{:x}", Sha256::digest(b"NEW-BASELINE"))),
        ];
        prepare_pull_transaction(&held, &backups, &next, Vec::new()).unwrap();
        held.atomic_write("a.md", b"NEW-A", false, 0o600).unwrap();
        held.atomic_write(SYNC_BASELINE_FILE, b"NEW-BASELINE", false, 0o600)
            .unwrap();

        assert!(recover_pull_transaction(&held).unwrap());
        assert_eq!(std::fs::read(root_path.join("a.md")).unwrap(), b"NEW-A");
        assert_eq!(
            std::fs::read(root_path.join(SYNC_BASELINE_FILE)).unwrap(),
            b"NEW-BASELINE"
        );
        assert!(!root_path.join(PULL_JOURNAL_FILE).exists());
        assert!(std::fs::read_dir(&root_path).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(PULL_BACKUP_PREFIX)
        }));
    }

    #[test]
    fn pull_journal_rejects_paths_outside_its_private_namespace() {
        let sha = "1".repeat(64);
        let journal = PullJournal {
            version: 1,
            phase: PullJournalPhase::Ready,
            backup_dir: format!("{PULL_BACKUP_PREFIX}{}", "a".repeat(32)),
            previous_baseline_sha256: sha.clone(),
            next_baseline_sha256: sha.clone(),
            created_directories: vec!["../outside".to_string()],
            entries: vec![PullJournalEntry {
                path: SYNC_BASELINE_FILE.to_string(),
                backup: Some("00000000".to_string()),
                old_sha256: Some(sha.clone()),
                old_mode: Some(0o600),
                old_readonly: Some(false),
                new_sha256: Some(sha),
            }],
        };
        let error = validate_pull_journal(journal).unwrap_err();
        assert!(error.contains("unsafe created directory"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn held_export_rollback_cannot_be_redirected_by_a_root_swap() {
        let temp = tempfile::tempdir().unwrap();
        let temp = std::fs::canonicalize(temp.path()).unwrap();
        let root_path = temp.join("out");
        let parked = temp.join("parked");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(root_path.join("existing.md"), b"OLD").unwrap();
        let held = crate::safe_path::SafeDir::open(&root_path).unwrap();
        let mut backups = snapshot_held_destinations(&held, &["existing.md".to_string()]).unwrap();
        held.atomic_write("existing.md", b"NEW", true, 0o600)
            .unwrap();
        backups[0].installed = Some(
            capture_installed_state(&held, "existing.md", Sha256::digest(b"NEW").into()).unwrap(),
        );

        std::fs::rename(&root_path, &parked).unwrap();
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(root_path.join("existing.md"), b"REPLACEMENT").unwrap();
        rollback_held_export(&held, &backups, &[]).unwrap();
        assert_eq!(std::fs::read(parked.join("existing.md")).unwrap(), b"OLD");
        assert_eq!(
            std::fs::read(root_path.join("existing.md")).unwrap(),
            b"REPLACEMENT"
        );
    }

    #[test]
    fn bounded_export_decompression_does_not_trust_a_declared_size() {
        let mut hostile = std::io::Cursor::new(vec![b'x'; 4096]);
        let error = read_bounded(&mut hostile, 1024).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("remaining store limit"));
        assert_eq!(
            hostile.position(),
            1025,
            "read one sentinel byte and stop instead of buffering the stream"
        );
    }

    #[test]
    fn normalize_pops_parents_lexically() {
        assert_eq!(
            normalize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
    }

    #[test]
    fn secret_name_shape_matches_the_hub_gate() {
        // ^[A-Za-z][A-Za-z0-9_-]{0,63}$ — mirrored exactly, boundaries included.
        let max = "A".repeat(64);
        for good in ["A", "stripe-key", "A1_B2_C3", "OpenAI_API-key", &max] {
            assert!(parse_secret_name(good).is_ok(), "should accept {good}");
        }
        let over = "A".repeat(65);
        for bad in [
            "",
            "1LEADING",
            "_LEADING",
            "HAS SPACE",
            "HAS.DOT",
            "Ä",
            "A\n",
            &over,
        ] {
            assert!(
                parse_secret_name(bad).is_err(),
                "should reject {}",
                bad.escape_debug()
            );
        }
    }

    #[test]
    fn human_size_speaks_the_hub_limit_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(256 * 1024 * 1024), "256.0 MiB");
        assert_eq!(human_size(512 * 1024 * 1024), "512.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn commas_group_thousands() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1000), "1,000");
        assert_eq!(commas(100_000), "100,000");
        assert_eq!(commas(1_234_567), "1,234,567");
    }

    #[test]
    fn query_target_resolves_positional_flag_and_conflicts() {
        let s = |v: &str| Some(v.to_string());
        // Positional form, unchanged.
        assert_eq!(
            resolve_query_target(None, s("b"), s("text")),
            Ok(("b".into(), Some("text".into())))
        );
        assert_eq!(
            resolve_query_target(None, s("b"), None),
            Ok(("b".into(), None))
        );
        // The flag alone, and the flag with text.
        assert_eq!(
            resolve_query_target(s("b"), None, None),
            Ok(("b".into(), None))
        );
        assert_eq!(
            resolve_query_target(s("b"), s("text"), None),
            Ok(("b".into(), Some("text".into())))
        );
        // Both forms: same brain proceeds, different brains refuse.
        assert_eq!(
            resolve_query_target(s("b"), s("b"), s("text")),
            Ok(("b".into(), Some("text".into())))
        );
        assert!(resolve_query_target(s("b"), s("other"), s("text"))
            .unwrap_err()
            .contains("--brain"));
        // No brain anywhere.
        assert!(resolve_query_target(None, None, None)
            .unwrap_err()
            .contains("which brain"));
    }

    fn emit_of(files: &[(&str, &[&str])]) -> Value {
        json!({
            "store": ".",
            "files": files
                .iter()
                .map(|(path, links)| json!({ "path": path, "links": links }))
                .collect::<Vec<_>>(),
            "summary": { "files": files.len() },
        })
    }

    fn seeds_of(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }

    fn sorted(set: BTreeSet<String>) -> Vec<String> {
        set.into_iter().collect()
    }

    #[test]
    fn incoming_link_counts_reports_the_hosted_dangle_heaviest_first() {
        // The dogfood shape: one high-fan-in source (`export.md`) named by
        // three records, plus a second marked file nothing links to.
        let emit = emit_of(&[
            ("records/a.md", &["sources/export.md"]),
            ("records/b.md", &["sources/export.md"]),
            ("records/c.md", &["sources/export.md", "records/lonely.md"]),
            ("sources/export.md", &["sources/export.md"]), // self-link: not a dangle
            ("records/lonely.md", &[]),
            ("records/unmarked.md", &["records/a.md"]),
        ]);
        let marked = seeds_of(&["sources/export.md", "records/lonely.md"]);
        assert_eq!(
            incoming_link_counts(&emit, &marked),
            vec![
                ("sources/export.md".to_string(), 3),
                ("records/lonely.md".to_string(), 1),
            ],
            "heaviest first; a file's self-link leaves with its own text"
        );
    }

    #[test]
    fn incoming_link_counts_is_empty_when_nothing_points_at_the_marked_set() {
        let emit = emit_of(&[("records/a.md", &["records/b.md"]), ("records/b.md", &[])]);
        assert!(incoming_link_counts(&emit, &seeds_of(&["records/orphan.md"])).is_empty());
    }

    #[test]
    fn closure_component_walks_links_undirected() {
        // a → b ← c: seeding a reaches c THROUGH b against the arrows.
        let emit = emit_of(&[
            ("a.md", &["b.md"]),
            ("b.md", &[]),
            ("c.md", &["b.md"]),
            ("d.md", &[]),
        ]);
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["a.md"]))),
            ["a.md", "b.md", "c.md"],
            "undirected through b; the isolated d stays out"
        );
    }

    #[test]
    fn closure_component_never_bridges_through_db_md_or_dangling_targets() {
        // DB.md links half the store — it must not connect components. Two
        // files sharing only a DANGLING target are not connected either.
        let emit = emit_of(&[
            ("DB.md", &["a.md", "d.md"]),
            ("a.md", &["DB.md"]),
            ("d.md", &[]),
            ("e.md", &["ghost.md"]),
            ("f.md", &["ghost.md"]),
        ]);
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["a.md"]))),
            ["a.md"],
            "DB.md is not a node, so it bridges nothing"
        );
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["e.md"]))),
            ["e.md"],
            "a dangling target is nobody's bridge"
        );
    }

    #[test]
    fn closure_component_keeps_unknown_seeds_and_survives_self_links() {
        let emit = emit_of(&[("g.md", &["g.md", "h.md"]), ("h.md", &[])]);
        // A seed emit never saw (e.g. a root-level hit file outside the
        // sources/records layers) rides through untouched.
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["outside.md"]))),
            ["outside.md"]
        );
        // A self-link is ignored; the real edge still walks.
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["g.md"]))),
            ["g.md", "h.md"]
        );
    }

    #[test]
    fn closure_component_tolerates_shapeless_emit_json() {
        assert_eq!(
            sorted(closure_component(&json!({}), &seeds_of(&["a.md"]))),
            ["a.md"],
            "no files array: the seeds are the component"
        );
    }

    #[test]
    fn adopt_names_are_contextual_deterministic_and_collision_safe() {
        let value = format!("sk-proj-{}", "a".repeat(24));
        let content = format!("api key: {value}\n");
        let start = content.find(&value).unwrap();
        assert_eq!(
            contextual_secret_name(&content, start, "OpenAI API key"),
            "API_KEY"
        );
        assert_eq!(
            contextual_secret_name(&value, 0, "OpenAI API key"),
            "OPENAI_API_KEY"
        );
        let hash = format!("{:x}", Sha256::digest(value.as_bytes()));
        assert_eq!(disambiguated_name("API_KEY", &hash, 0), "API_KEY");
        assert_eq!(
            disambiguated_name("API_KEY", &hash, 1),
            format!("API_KEY_{}", &hash[..8])
        );
        assert!(disambiguated_name(&"A".repeat(64), &hash, 16).len() <= 64);
    }

    #[test]
    fn adopt_rewrite_replaces_every_literal_and_merges_provenance() {
        let first = format!("sk-proj-{}", "a".repeat(24));
        let second = format!("ghp_{}", "b".repeat(36));
        let content = format!(
            "---\r\ntype: note\r\nupdated: 2026-01-01T00:00:00Z\r\nredacted: [{{\"name\":\"OLD_KEY\",\"kind\":\"previous\"}}]\r\n---\r\nopenai: {first}\r\ngithub: {second}\r\nagain: {first}\r\n"
        );
        let mut occurrences = Vec::new();
        let mut mappings = BTreeMap::new();
        for span in crate::scan::content_secret_spans(&content).unwrap() {
            let bytes = &content.as_bytes()[span.start..span.end];
            let hash = format!("{:x}", Sha256::digest(bytes));
            let name = if bytes == first.as_bytes() {
                "OPENAI_KEY"
            } else {
                "GITHUB_KEY"
            };
            mappings.insert(hash.clone(), name.to_string());
            occurrences.push(AdoptOccurrence {
                hash,
                start: span.start,
                end: span.end,
                line: 0,
                kind: span.kind,
            });
        }
        let next = rewritten_adopt_file(&content, &occurrences, &mappings, "2026-08-10T12:34:56Z")
            .unwrap();
        assert!(!next.contains(&first));
        assert!(!next.contains(&second));
        assert_eq!(next.matches("$OPENAI_KEY").count(), 2);
        assert_eq!(next.matches("$GITHUB_KEY").count(), 1);
        assert!(next.contains("updated: 2026-08-10T12:34:56Z\r\n"));
        assert!(next.contains("OLD_KEY"));
        assert!(next.contains("OPENAI_KEY"));
        assert!(next.contains("GITHUB_KEY"));
        assert!(next.contains("\r\n---\r\n"), "CRLF shape stays intact");
    }

    #[test]
    fn adopt_provenance_refuses_ambiguous_frontmatter_before_mutation() {
        let additions = [RedactedProvenance {
            name: "API_KEY".into(),
            kind: "OpenAI API key".into(),
        }]
        .into_iter()
        .collect();
        for bad in [
            "no frontmatter",
            "---\ntype: note\n",
            "---\nupdated: one\nupdated: two\n---\nbody",
            "---\nredacted:\n---\nbody",
            "---\nredacted: [{\"name\":\"bad.name\",\"kind\":\"x\"}]\n---\nbody",
        ] {
            assert!(
                apply_redacted_provenance(bad, &additions, "2026-08-10T00:00:00Z").is_err(),
                "must refuse {bad:?}"
            );
        }
    }

    #[test]
    fn trim_one_newline_trims_exactly_one() {
        let trim = |value: &str| trim_one_newline(value.as_bytes().to_vec());
        assert_eq!(trim("v\n"), b"v");
        assert_eq!(trim("v"), b"v");
        assert_eq!(trim("v\n\n"), b"v\n"); // exactly one
        assert_eq!(trim("v\r\n"), b"v"); // CRLF is one newline
        assert_eq!(trim("v\r"), b"v\r"); // a bare CR is data
        assert_eq!(trim("\n"), b"");
        assert_eq!(trim("multi\nline\n"), b"multi\nline");
        assert_eq!(trim_one_newline(vec![0xff, b'\n']), vec![0xff]);
    }
}
