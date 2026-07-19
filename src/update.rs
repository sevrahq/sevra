//! Versioning + signed self-update. Unlike the retired TS CLI (versionless,
//! coupled to the hub deploy), the Rust binary is release-versioned: the hub
//! reports the latest release at /api/hub/versions, and the CLI downloads the
//! platform asset from GitHub releases, verifies its Ed25519 signature against
//! the pinned publisher key, and atomically replaces its own file. The running
//! process finishes on loaded code; the new build applies next run. The
//! flyctl model, with signing.
//!
//! `SEVRA_NO_AUTO_UPDATE=1` disables the auto path entirely (no request, no
//! notice); `sevra update` stays the explicit path.

use std::fs;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

use crate::config::Config;
use crate::output::{fail, json_mode, note, out};
use crate::signing;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASES: &str = "https://github.com/sevrahq/sevra/releases/download";
/// The origin's independently deployed digest manifest (the same endpoint the
/// installers verify against). Overridable for testing against a local hub.
fn trusted_manifest_base() -> String {
    crate::config::env_nonempty("SEVRA_TRUSTED_MANIFEST_BASE")
        .unwrap_or_else(|| "https://www.sevrahq.com/api/hub/releases/sevra".to_string())
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The digest the origin vouches for, or None when it does not serve one
/// (unreachable, unknown version, non-digest body). None means "no second
/// opinion available", never "approved".
fn trusted_digest(version: &str, asset: &str) -> Option<String> {
    let url = format!("{}/{version}/{asset}", trusted_manifest_base());
    let body = download(&url).ok()?;
    let text = String::from_utf8(body).ok()?.trim().to_lowercase();
    let ok = text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit());
    ok.then_some(text)
}

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
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        // Also serves Windows-on-ARM: the x64 binary runs under emulation,
        // and because target_arch is baked at compile time, an emulated
        // binary self-updates onto the same x64 asset — consistent forever.
        "windows-x86_64"
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    {
        "unsupported"
    }
}

/// Release assets are bare binaries on unix and carry `.exe` on Windows
/// (`sevra-windows-x86_64.exe`) so the downloaded file is directly runnable.
fn asset_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    }
}

/// The aside name a Windows self-swap parks the running exe under:
/// `<full file name>.old.<pid>` — appended to the whole name, never via
/// `with_extension` (which would eat `.exe`).
#[cfg_attr(not(windows), allow(dead_code))]
fn swap_aside_path(p: &std::path::Path) -> std::path::PathBuf {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "sevra".to_string());
    p.with_file_name(format!("{name}.old.{}", std::process::id()))
}

/// True for the parked leftovers of a previous self-swap of `exe_name`.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_stale_swap_name(name: &str, exe_name: &str) -> bool {
    name.strip_prefix(exe_name)
        .and_then(|rest| rest.strip_prefix(".old."))
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

/// Best-effort removal of `<exe>.old.<pid>` siblings parked by previous
/// Windows self-swaps: the OLD exe stays delete-locked until its process
/// exits, so the swap defers cleanup to the NEXT launch — this call. No-op on
/// unix and on any error (a locked or missing file is fine).
pub fn cleanup_stale_swaps() {
    #[cfg(windows)]
    {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let Some(name) = exe.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return;
        };
        let Some(dir) = exe.parent() else { return };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let entry_name = entry.file_name().to_string_lossy().into_owned();
            if is_stale_swap_name(&entry_name, &name) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
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

const MAX_ASSET_BYTES: u64 = 64 * 1024 * 1024;

fn download(url: &str) -> Result<Vec<u8>, String> {
    let resp = agent()
        .get(url)
        .call()
        .map_err(|e| format!("download failed {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_ASSET_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed {url}: {e}"))?;
    // Refuse oversize EXPLICITLY: silently truncating would surface later as
    // a signature-verification failure — a false security alarm.
    if buf.len() as u64 > MAX_ASSET_BYTES {
        return Err(format!(
            "asset exceeds {} MB, refusing: {url}",
            MAX_ASSET_BYTES / (1024 * 1024)
        ));
    }
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
    let base = format!("{RELEASES}/v{version}/sevra-{target}{}", asset_suffix());
    let binary = download(&base)?;
    let sig = String::from_utf8(download(&format!("{base}.sig"))?)
        .map_err(|_| "signature is not text".to_string())?;
    if !signing::verify(&binary, &sig) {
        return Err(format!(
            "signature verification FAILED for {base} — refusing to replace the CLI (report: https://www.sevrahq.com/security)"
        ));
    }
    // Second, INDEPENDENT root of trust, matching what the installers do: the
    // signature proves the publisher key signed this, but that key is one
    // secret in one place. The hub serves the expected digest from a separately
    // deployed manifest, so a signing-key compromise alone is no longer enough
    // to push a binary onto every installed CLI unattended.
    //
    // Deliberately fail-OPEN on a missing/unreachable digest and fail-CLOSED on
    // a mismatch: a manifest outage must not brick self-update fleet-wide (the
    // signature still gates it), but a served digest that disagrees is a stop.
    if let Some(expected) = trusted_digest(version, &format!("sevra-{target}{}", asset_suffix())) {
        let actual = hex_sha256(&binary);
        if actual != expected {
            return Err(format!(
                "digest mismatch for {base}: the Sevra manifest expects {expected}, got {actual} — refusing to replace the CLI (report: https://www.sevrahq.com/security)"
            ));
        }
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
    #[cfg(windows)]
    {
        // Windows refuses a rename ONTO a running exe but allows renaming the
        // running exe ASIDE. Swap: self → `sevra.exe.old.<pid>` (delete-locked
        // until this process exits; removed by cleanup_stale_swaps on the next
        // launch), then tmp → self. A failed second step rolls the original
        // back, so an interrupted update never leaves a missing binary.
        let old = swap_aside_path(&self_path);
        fs::rename(&self_path, &old).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("replace failed (staging the running exe aside): {e}")
        })?;
        if let Err(e) = fs::rename(&tmp, &self_path) {
            let _ = fs::rename(&old, &self_path);
            let _ = fs::remove_file(&tmp);
            return Err(format!("replace failed: {e}"));
        }
        // Usually still locked by this very process; the next launch sweeps it.
        let _ = fs::remove_file(&old);
    }
    #[cfg(not(windows))]
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
    fn swap_aside_keeps_the_full_file_name() {
        // `with_extension` would turn sevra.exe into sevra.old.<pid> and eat
        // `.exe` — the aside path must append to the WHOLE name instead.
        // (Forward-slash paths so file_name() parses on every host OS.)
        let aside = swap_aside_path(std::path::Path::new("bin/sevra.exe"));
        let name = aside.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("sevra.exe.old."));
        let aside = swap_aside_path(std::path::Path::new("/usr/local/bin/sevra"));
        let name = aside.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("sevra.old."));
    }

    #[test]
    fn stale_swap_name_matching_is_strict() {
        assert!(is_stale_swap_name("sevra.exe.old.1234", "sevra.exe"));
        assert!(is_stale_swap_name("sevra.old.7", "sevra"));
        // Not ours: wrong exe, missing pid, non-numeric pid, unrelated files.
        assert!(!is_stale_swap_name("sevra.exe.old.", "sevra.exe"));
        assert!(!is_stale_swap_name("sevra.exe.old.abc", "sevra.exe"));
        assert!(!is_stale_swap_name("other.exe.old.12", "sevra.exe"));
        assert!(!is_stale_swap_name("sevra.exe", "sevra.exe"));
        assert!(!is_stale_swap_name("sevra.exe.new.12", "sevra.exe"));
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

    #[test]
    fn hex_sha256_matches_the_known_digest() {
        // The empty-string SHA-256, so the helper feeding digest comparison is
        // pinned to a value anyone can check.
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hex_sha256(b"abc").len(), 64);
        assert!(hex_sha256(b"abc").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn trusted_digest_rejects_anything_that_is_not_a_bare_digest() {
        // A 404 page, an HTML error, or a truncated value must read as "no
        // second opinion", never as an approval. Exercised through the same
        // shape-check the fetch path applies.
        let looks_like_digest = |t: &str| {
            let t = t.trim().to_lowercase();
            t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())
        };
        assert!(looks_like_digest(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!looks_like_digest("<!doctype html><title>404</title>"));
        assert!(!looks_like_digest("release asset is not trusted"));
        assert!(!looks_like_digest(""));
        assert!(!looks_like_digest("e3b0c442"));
        assert!(!looks_like_digest(&"z".repeat(64)));
    }
}
