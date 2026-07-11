//! The hub client: one ureq agent, an HTTPS guard (the bearer key never
//! travels in cleartext; loopback exempt), and the request/response contract
//! matching the TS CLI — a 2xx without JSON is refused as "not a Sevra hub
//! answer", and every >=400 fails with the hub's own error string.

use std::io::Read;

use serde_json::Value;

use crate::config::{config_path, Config};
use crate::output::fail;

/// The most the CLI will buffer from one hub response. ureq's `into_string()`
/// stops at 10 MB, which a large brain's `export` legitimately exceeds — so
/// bodies are read through an explicit reader with a cap sized for the
/// biggest honest payload (a full-store export), refused loudly past it.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

/// The bearer key must never travel in cleartext; only loopback hosts may skip
/// TLS (local dev against `npm run dev`).
pub fn assert_safe_hub(hub: &str) {
    // Minimal scheme/host parse — we control the shape (scheme://host[:port]).
    let (scheme, rest) = match hub.split_once("://") {
        Some(v) => v,
        None => fail(&format!("invalid hub URL: {hub}"), None),
    };
    // Host = authority up to the first '/', minus any port — with the
    // bracketed-IPv6 form handled so `http://[::1]:3000` counts as loopback.
    let hostport = rest.split('/').next().unwrap_or("");
    let host = match hostport.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => hostport.split(':').next().unwrap_or(""),
    };
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if scheme != "https" && !loopback {
        fail(
            &format!("refusing non-HTTPS hub {hub} — your API key would travel in cleartext (localhost is exempt)"),
            None,
        );
    }
}

pub struct HubResponse {
    pub status: u16,
    pub body: Option<Value>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(concat!("sevra/", env!("CARGO_PKG_VERSION")))
        // A hung hub must never hang an agent's loop: bounded connect, and a
        // read window sized for a 4 MB push on a slow link.
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(120))
        .build()
}

/// A key must be a clean header token before it is placed in the bearer
/// header: ureq rejects bad header VALUES with an error that echoes the whole
/// header line — key included — so a stray newline from a copy/paste would
/// otherwise leak the secret into stdout/stderr. Trim the usual paste
/// artifacts, then refuse anything still outside the printable-ASCII token
/// range WITHOUT echoing the key.
pub fn clean_key(raw: &str) -> String {
    let k = raw.trim();
    if k.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
        fail(
            "the API key contains whitespace or non-ASCII characters — re-copy it from the dashboard (the key is not shown here on purpose)",
            None,
        );
    }
    k.to_string()
}

/// Perform a hub request. `auth` toggles the bearer header (the caller passes
/// false only for the login probe, which supplies its own key inline).
pub fn request(
    cfg: &Config,
    method: &str,
    path: &str,
    body: Option<&Value>,
    auth: bool,
) -> HubResponse {
    assert_safe_hub(&cfg.hub);
    let url = format!("{}{}", cfg.hub, path);
    let mut req = agent().request(method, &url);
    if auth {
        match &cfg.key {
            Some(k) => req = req.set("authorization", &format!("Bearer {}", clean_key(k))),
            None => fail(
                "not logged in — run `sevra login --key vc_account_…` (get a key from the dashboard)",
                None,
            ),
        }
    }

    let result = match body {
        Some(v) => {
            req = req.set("content-type", "application/json");
            req.send_string(&v.to_string())
        }
        None => req.call(),
    };

    let (status, resp) = match result {
        Ok(resp) => (resp.status(), Some(resp)),
        Err(ureq::Error::Status(code, resp)) => (code, Some(resp)),
        Err(ureq::Error::Transport(t)) => {
            fail(&format!("hub unreachable at {}: {}", cfg.hub, t), None)
        }
    };

    let resp = resp.unwrap();
    // Release-versioned staleness check (once per process; version-based, not
    // deploy-coupled): the CLI learns the latest release from the hub and
    // signed-self-updates when behind.
    crate::update::maybe_auto_update(cfg);
    let mut buf = Vec::new();
    if let Err(e) = resp
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut buf)
    {
        fail(
            &format!(
                "reading the hub's response failed mid-body: {e} (hub: {})",
                cfg.hub
            ),
            None,
        );
    }
    if buf.len() as u64 > MAX_RESPONSE_BYTES {
        fail(
            &format!(
                "hub response exceeded {} MB — refusing to buffer it",
                MAX_RESPONSE_BYTES / (1024 * 1024)
            ),
            None,
        );
    }
    let text = String::from_utf8_lossy(&buf);
    let parsed: Option<Value> = serde_json::from_str(&text).ok();
    HubResponse {
        status,
        body: parsed,
    }
}

/// Unwrap a successful JSON body, or fail. A >=400 surfaces the hub's own
/// `error`; a 2xx without JSON (captive portal, wrong URL, proxy) is refused
/// here rather than deserializing into nothing downstream.
pub fn ensure_ok(r: HubResponse, what: &str) -> Value {
    if r.status >= 400 {
        let msg = r
            .body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error")
            .to_string();
        fail(&format!("{what} failed (HTTP {}): {msg}", r.status), r.body);
    }
    match r.body {
        Some(b) => b,
        None => fail(
            &format!(
                "{what} failed: the hub answered HTTP {} with a non-JSON body — check your hub URL (`sevra whoami`, config: {})",
                r.status,
                config_path().display()
            ),
            None,
        ),
    }
}
