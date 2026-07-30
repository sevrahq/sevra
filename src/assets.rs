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
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::commands::{contained, human_size};
use crate::config::Config;
use crate::hub::{ensure_ok, get_presigned, put_presigned, request};
use crate::local::LocalScope;
use crate::output::{fail, note};

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
    let assets = rows
        .iter()
        .filter_map(|row| {
            let path = row.get("path")?.as_str()?.to_string();
            let sha256 = row.get("sha256")?.as_str()?.to_string();
            let bytes = row.get("bytes")?.as_u64()?;
            (sha256.len() == 64).then_some(MissingAsset {
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
            // Find a readable, non-kept-home copy whose bytes still match the
            // manifest. A drifted file (edited since `dbmd assets scan`) is
            // named and skipped — re-scan and push again to update the
            // declaration.
            let mut bytes: Option<Vec<u8>> = None;
            let mut kept = 0usize;
            let mut absent = 0usize;
            for path in paths {
                if scope.is_some_and(|s| s.keeps_home(path)) {
                    kept += 1;
                    continue;
                }
                let Some(abs) = contained(root, path) else {
                    absent += 1;
                    continue;
                };
                match std::fs::read(&abs) {
                    Ok(data) => {
                        let actual = format!("{:x}", Sha256::digest(&data));
                        if actual == *sha256 && data.len() as u64 == *declared_bytes {
                            bytes = Some(data);
                            break;
                        }
                        note(&format!(
                            "asset {path} drifted since `dbmd assets scan` (bytes or hash changed) — re-scan and push to update the manifest"
                        ));
                        report.drifted += 1;
                    }
                    Err(_) => absent += 1,
                }
            }
            let Some(bytes) = bytes else {
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
            put_presigned(
                url,
                presigned.get("headers").unwrap_or(&Value::Null),
                &bytes,
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
                human_size(bytes.len() as u64)
            ));
            report.uploaded += 1;
            report.uploaded_bytes += bytes.len() as u64;
            progressed = true;
        }

        if !truncated || !progressed {
            break;
        }
    }
    report
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

/// Restore every `assets.jsonl` entry beside an exported store: entries whose
/// file is absent or does not match the manifest hash are downloaded through
/// the presigned GET flow, SHA-verified, and written under `root` (path
/// containment enforced — the manifest is remote content). Returns `None`
/// when the export carries no manifest.
pub fn restore_assets(cfg: &Config, brain: &str, root: &Path) -> Option<RestoreReport> {
    let manifest = std::fs::read_to_string(root.join("assets.jsonl")).ok()?;
    let mut report = RestoreReport {
        restored: 0,
        restored_bytes: 0,
        present: 0,
        failed: 0,
    };

    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue; // dbmd validates the manifest; a bad line is its report to make
        };
        let (Some(path), Some(sha256)) = (
            entry.get("path").and_then(Value::as_str),
            entry.get("sha256").and_then(Value::as_str),
        ) else {
            continue;
        };
        let declared_bytes = entry.get("bytes").and_then(Value::as_u64);
        let Some(abs) = contained(root, path) else {
            note(&format!("refusing unsafe asset path from manifest: {path}"));
            report.failed += 1;
            continue;
        };
        if let Ok(data) = std::fs::read(&abs) {
            if format!("{:x}", Sha256::digest(&data)) == sha256 {
                report.present += 1;
                continue;
            }
        }

        let presigned = ensure_ok(
            request(
                cfg,
                "GET",
                &format!(
                    "/api/hub/brains/{}/assets/presign?sha256={}&action=get",
                    enc(brain),
                    sha256
                ),
                None,
                true,
            ),
            "prepare asset download",
        );
        let Some(url) = presigned.get("url").and_then(Value::as_str) else {
            note(&format!(
                "hub returned no download URL for {path} — skipped"
            ));
            report.failed += 1;
            continue;
        };
        // Cap the read at the declared size (when the manifest carries one):
        // the hub's copy was confirmed at that exact length.
        let cap = declared_bytes.unwrap_or(u64::MAX).max(1);
        let data = get_presigned(url, cap);
        if format!("{:x}", Sha256::digest(&data)) != sha256 {
            note(&format!(
                "downloaded asset failed SHA-256 verification: {path} — skipped"
            ));
            report.failed += 1;
            continue;
        }
        if let Some(parent) = abs.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&abs, &data).is_err() {
            note(&format!("could not write asset {path} — skipped"));
            report.failed += 1;
            continue;
        }
        report.restored += 1;
        report.restored_bytes += data.len() as u64;
    }
    Some(report)
}
