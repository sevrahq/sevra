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
}

#[derive(Debug, Clone)]
pub struct Config {
    pub hub: String,
    pub key: Option<String>,
}

pub fn config_dir() -> PathBuf {
    home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sevra")
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
    match fs::read_to_string(config_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(), // a corrupt file reads as empty
        Err(_) => FileConfig::default(),
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
/// world-readable, not even for the write-then-chmod window. Written to a
/// 0600 temp file in the same dir, then renamed over the target (atomic on
/// POSIX). Non-Unix platforms get default perms under the user profile.
pub fn save(hub: &str, key: &str) -> std::io::Result<()> {
    let dir = config_dir();
    fs::create_dir_all(&dir)?;
    let path = config_path();
    let body = serde_json::to_string_pretty(&FileConfig {
        hub: Some(strip_trailing_slash(hub)),
        key: Some(key.to_string()),
    })
    .unwrap();
    let tmp = dir.join(format!("config.json.new.{}", std::process::id()));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(format!("{body}\n").as_bytes())?;
    }
    #[cfg(not(unix))]
    fs::write(&tmp, format!("{body}\n"))?;
    fs::rename(&tmp, &path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(())
}

pub fn remove() -> bool {
    fs::remove_file(config_path()).is_ok()
}
