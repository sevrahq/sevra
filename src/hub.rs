//! The hub client: one ureq agent, an HTTPS guard (the bearer key never
//! travels in cleartext; loopback exempt), and the request/response contract
//! matching the TS CLI — a 2xx without JSON is refused as "not a Sevra hub
//! answer", and every >=400 fails with the hub's own error string.

use serde_json::Value;

use crate::config::{config_path, Config};
use crate::output::fail;

/// The bearer key must never travel in cleartext; only loopback hosts may skip
/// TLS (local dev against `npm run dev`).
pub fn assert_safe_hub(hub: &str) {
    // Minimal scheme/host parse — we control the shape (scheme://host[:port]).
    let (scheme, rest) = match hub.split_once("://") {
        Some(v) => v,
        None => fail(&format!("invalid hub URL: {hub}"), None),
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
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
        .build()
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
            Some(k) => req = req.set("authorization", &format!("Bearer {k}")),
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
    let text = resp.into_string().unwrap_or_default();
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
        fail(
            &format!("{what} failed (HTTP {}): {msg}", r.status),
            r.body,
        );
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
