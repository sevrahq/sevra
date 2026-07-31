//! Config: `~/.sevra/config.json`, written 0600 (the key is a credential).
//! Precedence, identical to the TS CLI: env (SEVRA_HUB_URL / SEVRA_API_KEY)
//! overrides the file, which overrides the default hub.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const DEFAULT_HUB: &str = "https://www.sevrahq.com";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub hub: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    // Set only when the key was minted by the browser sign-in flow (so
    // `logout` can revoke it server-side). Absent for a user-supplied
    // `--key`, which logout leaves untouched — the user may use it elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub hub: String,
    pub key: Option<String>,
}

pub fn config_dir() -> PathBuf {
    let home = home::home_dir().unwrap_or_else(|| PathBuf::from("."));
    // Resolve the trusted home itself (macOS exposes /var as a compatibility
    // symlink to /private/var), then keep `.sevra` as the untrusted component
    // that the no-follow capability layer must inspect/create.
    fs::canonicalize(&home).unwrap_or(home).join(".sevra")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

fn strip_trailing_slash(s: &str) -> String {
    s.strip_suffix('/').unwrap_or(s).to_string()
}

/// The raw file config (env-blind) — `login` uses this so a one-off
/// SEVRA_HUB_URL never becomes the stored default.
pub fn load_file() -> FileConfig {
    let dir = config_dir();
    match crate::safe_path::read_regular(&dir, "config.json") {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        // A missing, linked, malformed, or unreadable credential file reads
        // as empty. It is never followed through a reparse point.
        Ok(None) | Err(_) => FileConfig::default(),
    }
}

/// An env var, treated as absent when empty — matching the TS CLI's `||`
/// truthiness (`SEVRA_API_KEY=` falls through to the file, not an empty key).
pub fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The effective config: env over file over default.
pub fn load() -> Config {
    let file = load_file();
    let hub = env_nonempty("SEVRA_HUB_URL")
        .or(file.hub)
        .unwrap_or_else(|| DEFAULT_HUB.to_string());
    let key = env_nonempty("SEVRA_API_KEY").or(file.key);
    Config {
        hub: strip_trailing_slash(&hub),
        key,
    }
}

/// Persist hub + key, 0600 FROM CREATION — the credential must never be
/// world-readable, not even for the write-then-chmod window. Every platform
/// traverses through held, no-follow directory handles and atomically replaces
/// the leaf from an unpredictable same-directory temporary file.
pub fn save(hub: &str, key: &str, key_id: Option<&str>) -> std::io::Result<()> {
    let dir = config_dir();
    crate::safe_path::ensure_dir(&dir, 0o700)?;
    // The directory holds a credential; the umask default (often 0755) lets
    // anyone list it. Tighten it best-effort — a pre-existing dir owned by the
    // user is the normal case, and failing here must not block a login.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let body = serde_json::to_string_pretty(&FileConfig {
        hub: Some(strip_trailing_slash(hub)),
        key: Some(key.to_string()),
        key_id: key_id.map(String::from),
    })
    .unwrap();
    crate::safe_path::atomic_write(
        &dir,
        "config.json",
        format!("{body}\n").as_bytes(),
        false,
        0o600,
    )
}

/// Remove the credential file. Ok(true) = removed, Ok(false) = nothing to
/// remove; a file that exists but cannot be deleted is an Err (the caller
/// must NOT report a clean logout).
pub fn remove() -> std::io::Result<bool> {
    crate::safe_path::remove_regular(&config_dir(), "config.json")
}
