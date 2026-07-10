//! Versioning + signed self-update. Unlike the retired TS CLI (versionless,
//! coupled to the hub deploy), the Rust binary is release-versioned: the hub
//! reports the latest release at /api/hub/versions, and the CLI downloads the
//! platform asset from GitHub releases, verifies its Ed25519 signature against
//! the pinned publisher key, and atomically replaces its own file. The running
//! process finishes on loaded code; the new build applies next run. The
//! flyctl model, with signing.
//!
//! `SEVRA_NO_AUTO_UPDATE=1` downgrades the auto path to a one-line notice.

use std::fs;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

use crate::config::Config;
use crate::output::{fail, json_mode, note, out};
use crate::signing;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASES: &str = "https://github.com/sevrahq/sevra/releases/download";

static CHECKED: AtomicBool = AtomicBool::new(false);

/// The GitHub release asset name for the running platform (bare binary; CI
/// signs each one). Mirrors the install script's target detection.
pub fn asset_target() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "darwin-x86_64"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "darwin-aarch64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x86_64-musl"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "linux-aarch64-musl"
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        "unsupported"
    }
}

fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().trim_start_matches('v');
    let core = core.split('-').next().unwrap_or(core);
    let mut it = core.split('.');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

fn is_older(a: &str, b: &str) -> bool {
    match (parse_semver(a), parse_semver(b)) {
        (Some(x), Some(y)) => x < y,
        _ => false,
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(concat!("sevra/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// GET {hub}/api/hub/versions → parsed JSON, best-effort (None on any failure).
fn fetch_versions(hub: &str) -> Option<Value> {
    let url = format!("{hub}/api/hub/versions");
    let resp = agent().get(&url).call().ok()?;
    let text = resp.into_string().ok()?;
    serde_json::from_str(&text).ok()
}

fn download(url: &str) -> Result<Vec<u8>, String> {
    let resp = agent()
        .get(url)
        .call()
        .map_err(|e| format!("download failed {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(64 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed {url}: {e}"))?;
    Ok(buf)
}

/// Download the platform asset for `version`, verify its signature, and replace
/// the running binary atomically. Returns Ok on success.
fn download_verify_replace(version: &str) -> Result<(), String> {
    let target = asset_target();
    if target == "unsupported" {
        return Err("no release asset for this platform".into());
    }
    let base = format!("{RELEASES}/v{version}/sevra-{target}");
    let binary = download(&base)?;
    let sig = String::from_utf8(download(&format!("{base}.sig"))?)
        .map_err(|_| "signature is not text".to_string())?;
    if !signing::verify(&binary, &sig) {
        return Err(format!(
            "signature verification FAILED for {base} — refusing to replace the CLI (report: https://www.sevrahq.com/security)"
        ));
    }
    let self_path = std::env::current_exe().map_err(|e| format!("cannot locate self: {e}"))?;
    let self_path = fs::canonicalize(&self_path).unwrap_or(self_path);
    // Write-then-rename so a failed write can never leave a truncated CLI.
    let tmp = self_path.with_extension(format!("new.{}", std::process::id()));
    fs::write(&tmp, &binary).map_err(|e| format!("write failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod failed: {e}"))?;
    }
    fs::rename(&tmp, &self_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("replace failed: {e}")
    })?;
    Ok(())
}

/// Once-per-process auto-update, triggered from the hub client. Best-effort and
/// non-fatal: any failure downgrades to a one-line notice and never disturbs
/// the in-flight command. A signature failure is the one loud case.
pub fn maybe_auto_update(cfg: &Config) {
    if CHECKED.swap(true, Ordering::Relaxed) {
        return;
    }
    let versions = match fetch_versions(&cfg.hub) {
        Some(v) => v,
        None => return,
    };
    let latest = match versions
        .get("sevra")
        .and_then(|s| s.get("latest"))
        .and_then(|l| l.as_str())
    {
        Some(l) => l.to_string(),
        None => return,
    };
    if !is_older(VERSION, &latest) {
        return;
    }
    if std::env::var("SEVRA_NO_AUTO_UPDATE").is_ok() {
        note(&format!(
            "sevra {VERSION} is out of date ({latest} is available) — run `sevra update`"
        ));
        return;
    }
    match download_verify_replace(&latest) {
        Ok(()) => note(&format!(
            "auto-updated {VERSION} → {latest} (applies next run; SEVRA_NO_AUTO_UPDATE=1 disables)"
        )),
        Err(e) if e.contains("FAILED") => note(&format!("SECURITY: {e}")),
        Err(_) => note(&format!(
            "sevra {VERSION} is out of date ({latest} is available) — run `sevra update`"
        )),
    }
}

pub fn cmd_version() {
    out(
        &format!("sevra {VERSION}"),
        Some(json!({ "version": VERSION, "target": asset_target() })),
    );
}

/// Explicit `sevra update`: update self if a newer release exists, then report
/// dbmd's staleness (dbmd never auto-updates — a versioned standards tool).
pub fn cmd_update(cfg: &Config) {
    crate::hub::assert_safe_hub(&cfg.hub);
    let versions = fetch_versions(&cfg.hub).unwrap_or_else(|| {
        fail(
            &format!("could not reach {}/api/hub/versions", cfg.hub),
            None,
        )
    });
    let latest = versions
        .get("sevra")
        .and_then(|s| s.get("latest"))
        .and_then(|l| l.as_str())
        .unwrap_or(VERSION)
        .to_string();

    let mut data = serde_json::Map::new();
    let mut line;
    if is_older(VERSION, &latest) {
        match download_verify_replace(&latest) {
            Ok(()) => {
                line =
                    format!("updated {VERSION} → {latest} (signature verified; applies next run)");
                data.insert("from".into(), json!(VERSION));
                data.insert("to".into(), json!(latest));
                data.insert("updated".into(), json!(true));
            }
            Err(e) => {
                let msg = if e.contains("FAILED") {
                    format!("SECURITY: {e}")
                } else {
                    e
                };
                fail(&msg, None)
            }
        }
    } else {
        line = format!("already up to date ({VERSION})");
        data.insert("version".into(), json!(VERSION));
        data.insert("updated".into(), json!(false));
    }

    // dbmd staleness — reported, never auto-applied.
    if let Some(dbmd) = versions.get("dbmd") {
        if let Some(dbmd_latest) = dbmd.get("latest").and_then(|l| l.as_str()) {
            let installed = dbmd_installed_version();
            match &installed {
                None => {
                    line.push_str(&format!(
                        "\ndbmd: not installed — get it: curl -fsSL {}/install/dbmd.sh | sh",
                        cfg.hub
                    ));
                    data.insert(
                        "dbmd".into(),
                        json!({ "installed": null, "latest": dbmd_latest }),
                    );
                }
                Some(v) if is_older(v, dbmd_latest) => {
                    line.push_str(&format!(
                        "\ndbmd {v} is behind {dbmd_latest} — update: curl -fsSL {}/install/dbmd.sh | sh",
                        cfg.hub
                    ));
                    data.insert(
                        "dbmd".into(),
                        json!({ "installed": v, "latest": dbmd_latest, "current": false }),
                    );
                }
                Some(v) => {
                    line.push_str(&format!("\ndbmd {v} — current"));
                    data.insert(
                        "dbmd".into(),
                        json!({ "installed": v, "latest": dbmd_latest, "current": true }),
                    );
                }
            }
        }
    }

    if json_mode() {
        out("", Some(Value::Object(data)));
    } else {
        out(&line, None);
    }
}

fn dbmd_installed_version() -> Option<String> {
    let output = std::process::Command::new("dbmd")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let core = s.split_whitespace().find(|t| parse_semver(t).is_some())?;
    parse_semver(core).map(|(a, b, c)| format!("{a}.{b}.{c}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_ordering() {
        assert!(is_older("0.1.0", "0.2.0"));
        assert!(is_older("0.1.0", "1.0.0"));
        assert!(!is_older("1.0.0", "0.9.9"));
        assert!(!is_older("0.1.0", "0.1.0"));
        assert!(is_older("0.1.0", "0.1.1-rc1"));
    }
}
