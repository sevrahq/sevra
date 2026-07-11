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

/// A version string safe to interpolate into the release-download URL: SemVer
/// charset only. The hub supplies this string, and while a hostile value can
/// never pass signature verification, it must not get to steer the URL path
/// either (`0.1.2-x/../../other-repo/...`).
fn safe_version_str(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(concat!("sevra/", env!("CARGO_PKG_VERSION")))
        // A hung endpoint must never hang the CLI: bounded connect, and a
        // generous read window (release binaries are ~2 MB).
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(120))
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
    if !safe_version_str(version) {
        return Err(format!(
            "refusing malformed version string from the hub: {version:?}"
        ));
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
    // Write-then-rename so a failed write can never leave a truncated CLI —
    // and a failed WRITE cleans its own partial temp up too.
    let tmp = self_path.with_extension(format!("new.{}", std::process::id()));
    fs::write(&tmp, &binary).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("write failed: {e}")
    })?;
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

/// Throttle: at most one background version check per day, stamped in
/// ~/.sevra/update-check. The retired TS CLI's staleness signal rode a
/// response header (zero extra requests); a versions fetch on every
/// invocation would tax every agent loop with a round trip, so the check is
/// daily. `stamp: false` peeks without consuming the daily slot; the deferred
/// runner stamps only when it actually checks. Best-effort: an unreadable/
/// unwritable stamp file just means "check now".
fn update_check_due(stamp: bool) -> bool {
    let path = crate::config::config_dir().join("update-check");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(prev) = fs::read_to_string(&path) {
        if let Ok(prev) = prev.trim().parse::<u64>() {
            if now.saturating_sub(prev) < 24 * 60 * 60 {
                return false;
            }
        }
    }
    if stamp {
        let _ = fs::create_dir_all(crate::config::config_dir());
        let _ = fs::write(&path, now.to_string());
    }
    true
}

/// The hub the deferred check should use, recorded by the hub client. Empty =
/// nothing scheduled.
static PENDING_HUB: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Called by the hub client after a response: RECORDS that a daily check is
/// due, never performs it — the in-flight command's latency stays untouched.
/// SEVRA_NO_AUTO_UPDATE=1 skips entirely (zero extra requests); `sevra
/// update` stays the explicit path.
pub fn maybe_auto_update(cfg: &Config) {
    if CHECKED.swap(true, Ordering::Relaxed) {
        return;
    }
    if std::env::var("SEVRA_NO_AUTO_UPDATE").is_ok() {
        return;
    }
    if !update_check_due(false) {
        return;
    }
    let _ = PENDING_HUB.set(cfg.hub.clone());
}

/// Runs at the END of main, after the command's output is flushed: the daily
/// version check and, when behind, the signed download + atomic self-replace.
/// Best-effort and non-fatal; a signature failure is the one loud case.
pub fn run_deferred_auto_update() {
    let Some(hub) = PENDING_HUB.get() else { return };
    if !update_check_due(true) {
        return; // another process consumed the slot since we peeked
    }
    let versions = match fetch_versions(hub) {
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
    // A hub that cannot resolve the latest release (e.g. GitHub rate-limited
    // behind it) must not read as "already up to date" — that's an unknown,
    // not a pass.
    let latest = match versions
        .get("sevra")
        .and_then(|s| s.get("latest"))
        .and_then(|l| l.as_str())
    {
        Some(l) => l.to_string(),
        None => fail(
            "the hub could not report the latest sevra release right now — try again shortly",
            None,
        ),
    };

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

    #[test]
    fn version_url_guard() {
        assert!(safe_version_str("0.1.2"));
        assert!(safe_version_str("0.1.2-rc1"));
        assert!(!safe_version_str("0.1.2-x/../../evil"));
        assert!(!safe_version_str("0.1.2%2f.."));
        assert!(!safe_version_str(""));
        assert!(!safe_version_str(&"9".repeat(65)));
    }
}
