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
const CONNECT_ATTEMPTS: usize = 3;
const CONNECT_RETRY_BACKOFF_MS: [u64; CONNECT_ATTEMPTS - 1] = [100, 300];

/// The bearer key must never travel in cleartext; only loopback hosts may skip
/// TLS (local dev against `npm run dev`).
pub fn assert_safe_hub(hub: &str) {
    let parsed =
        url::Url::parse(hub).unwrap_or_else(|_| fail(&format!("invalid hub URL: {hub}"), None));
    if !parsed.username().is_empty() || parsed.password().is_some() {
        fail("hub URLs must not contain userinfo", None);
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        fail("hub URLs must not contain a query or fragment", None);
    }
    let loopback = match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if parsed.scheme() != "https" && !loopback {
        fail(
            &format!("refusing non-HTTPS hub {hub} — your API key would travel in cleartext (localhost is exempt)"),
            None,
        );
    }
}

pub fn put_presigned(url: &str, headers: &Value, bytes: &[u8]) {
    let parsed = url::Url::parse(url)
        .unwrap_or_else(|_| fail("the hub returned an invalid upload URL", None));
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        fail("the hub returned an unsafe upload URL", None);
    }
    let http = agent();
    let result = with_connect_retries(|| {
        let mut req = http.put(url);
        if let Some(map) = headers.as_object() {
            for (name, value) in map {
                if let Some(value) = value.as_str() {
                    req = req.set(name, value);
                }
            }
        }
        req.send_bytes(bytes).map_err(Box::new)
    });
    match result {
        Ok(resp) if resp.status() < 300 => {}
        Ok(resp) => fail(
            &format!("pack upload failed (HTTP {})", resp.status()),
            None,
        ),
        Err(error) => match *error {
            ureq::Error::Status(code, _) => {
                fail(&format!("pack upload failed (HTTP {code})"), None)
            }
            ureq::Error::Transport(err) => fail(&format!("pack upload failed: {err}"), None),
        },
    }
}

pub fn get_presigned(url: &str, max_bytes: u64) -> Vec<u8> {
    let parsed = url::Url::parse(url)
        .unwrap_or_else(|_| fail("the hub returned an invalid download URL", None));
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        fail("the hub returned an unsafe download URL", None);
    }
    let http = agent();
    let resp = match with_connect_retries(|| http.get(url).call().map_err(Box::new)) {
        Ok(resp) => resp,
        Err(error) => match *error {
            ureq::Error::Status(code, _) => {
                fail(&format!("pack download failed (HTTP {code})"), None)
            }
            ureq::Error::Transport(err) => fail(&format!("pack download failed: {err}"), None),
        },
    };
    let mut out = Vec::new();
    resp.into_reader()
        .take(max_bytes + 1)
        .read_to_end(&mut out)
        .unwrap_or_else(|err| fail(&format!("pack download failed: {err}"), None));
    if out.len() as u64 > max_bytes {
        fail("pack download exceeded the supported size", None);
    }
    out
}

/// The one not-logged-in message (also used by `secrets set` to refuse BEFORE
/// prompting for a value it could never send).
pub const NOT_LOGGED_IN: &str =
    "not logged in — run `sevra login --key sevra_account_…` (get a key from the dashboard)";

pub struct HubResponse {
    pub status: u16,
    pub body: Option<Value>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(concat!("sevra/", env!("CARGO_PKG_VERSION")))
        // Redirects are never implicit on authenticated or presigned traffic.
        // A redirect can cross origins and strip or replay sensitive material;
        // callers receive the 3xx and fail it as a non-success instead.
        .redirects(0)
        // A hung hub must never hang an agent's loop: bounded connect, and a
        // read window sized for a large pack transfer on a slow link.
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(120))
        .build()
}

/// Retry only failures that happen before an HTTP request can reach the hub.
/// Mid-stream I/O is deliberately excluded because request bytes may already
/// have crossed the wire; replay safety then belongs to the verb's idempotency
/// contract, not a generic transport loop.
fn is_pre_request_transport(kind: ureq::ErrorKind) -> bool {
    matches!(
        kind,
        ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed | ureq::ErrorKind::ProxyConnect
    )
}

fn with_connect_retries(
    mut send: impl FnMut() -> Result<ureq::Response, Box<ureq::Error>>,
) -> Result<ureq::Response, Box<ureq::Error>> {
    let mut attempt = 0;
    loop {
        match send() {
            Err(error)
                if matches!(
                    error.as_ref(),
                    ureq::Error::Transport(transport)
                        if is_pre_request_transport(transport.kind())
                ) && attempt + 1 < CONNECT_ATTEMPTS =>
            {
                std::thread::sleep(std::time::Duration::from_millis(
                    CONNECT_RETRY_BACKOFF_MS[attempt],
                ));
                attempt += 1;
            }
            result => return result,
        }
    }
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
    let credential = if auth {
        match &cfg.key {
            Some(k) => Some(format!("Bearer {}", clean_key(k))),
            None => fail(NOT_LOGGED_IN, None),
        }
    } else {
        None
    };
    let encoded_body = body.map(Value::to_string);
    let http = agent();
    let result = with_connect_retries(|| {
        let mut req = http.request(method, &url);
        if let Some(value) = &credential {
            req = req.set("authorization", value);
        }
        match &encoded_body {
            Some(value) => req
                .set("content-type", "application/json")
                .send_string(value)
                .map_err(Box::new),
            None => req.call().map_err(Box::new),
        }
    });

    let (status, resp) = match result {
        Ok(resp) => (resp.status(), Some(resp)),
        Err(error) => match *error {
            ureq::Error::Status(code, resp) => (code, Some(resp)),
            ureq::Error::Transport(t) => {
                fail(&format!("hub unreachable at {}: {}", cfg.hub, t), None)
            }
        },
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

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn request_retries_a_connection_failure_before_sending() {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let server = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            let listener = TcpListener::bind(address).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_bytes = [0_u8; 1024];
            let _ = stream.read(&mut request_bytes).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                )
                .unwrap();
        });
        let cfg = Config {
            hub: format!("http://{address}"),
            key: None,
        };

        let response = request(&cfg, "GET", "/retry", None, false);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Some(serde_json::json!({ "ok": true })));
        server.join().unwrap();
    }
}
