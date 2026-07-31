//! The hub client: one ureq agent, an HTTPS guard (the bearer key never
//! travels in cleartext; loopback exempt), and the request/response contract
//! matching the TS CLI — a 2xx without JSON is refused as "not a Sevra hub
//! answer", and every >=400 fails with the hub's own error string.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

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

/// Presigned-transfer URL guard. Production transfers require HTTPS and a
/// public resolved address. A loopback transfer is accepted only when the
/// configured hub is itself loopback (local development/tests); a remote hub
/// can never use a presign answer as SSRF into the caller's machine, LAN, or
/// cloud metadata service.
fn host_is_loopback(parsed: &url::Url) -> bool {
    match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn public_transfer_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_unspecified()
                // Carrier-grade NAT and benchmark networks are not public
                // object-storage destinations.
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || octets[0] >= 240)
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || first & 0xfe00 == 0xfc00 // unique-local fc00::/7
                || first & 0xffc0 == 0xfe80 // link-local fe80::/10
                || first & 0xffc0 == 0xfec0 // deprecated site-local fec0::/10
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| !public_transfer_ip(IpAddr::V4(mapped))))
        }
    }
}

fn presigned_network_policy(cfg: &Config, parsed: &url::Url) -> Result<bool, &'static str> {
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err("userinfo and fragments are forbidden");
    }
    let hub = url::Url::parse(&cfg.hub).map_err(|_| "the configured hub URL is invalid")?;
    let local_dev = host_is_loopback(&hub) && host_is_loopback(parsed);
    if parsed.scheme() != "https" && !local_dev {
        return Err("non-HTTPS transfer URLs are forbidden");
    }
    if !local_dev {
        match parsed.host() {
            Some(url::Host::Ipv4(ip)) if !public_transfer_ip(IpAddr::V4(ip)) => {
                return Err("private or local transfer addresses are forbidden")
            }
            Some(url::Host::Ipv6(ip)) if !public_transfer_ip(IpAddr::V6(ip)) => {
                return Err("private or local transfer addresses are forbidden")
            }
            None => return Err("the transfer URL has no host"),
            _ => {}
        }
    }
    Ok(local_dev)
}

fn transfer_agent(allow_local: bool) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(concat!("sevra/", env!("CARGO_PKG_VERSION")))
        .redirects(0)
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(120))
        // Resolve exactly once for the connection and reject the complete DNS
        // answer if any address is private/local. The HTTP client consumes
        // this vetted vector directly, closing the resolve-check-resolve DNS
        // rebinding window.
        .resolver(move |netloc: &str| {
            let addresses: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
            if addresses.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "transfer host resolved to no addresses",
                ));
            }
            if !allow_local
                && addresses
                    .iter()
                    .any(|address| !public_transfer_ip(address.ip()))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "transfer host resolved to a private or local address",
                ));
            }
            Ok(addresses)
        })
        .build()
}

pub fn put_presigned(cfg: &Config, url: &str, headers: &Value, bytes: &[u8]) {
    let parsed = url::Url::parse(url)
        .unwrap_or_else(|_| fail("the hub returned an invalid upload URL", None));
    let allow_local = presigned_network_policy(cfg, &parsed)
        .unwrap_or_else(|_| fail("the hub returned an unsafe upload URL", None));
    let http = transfer_agent(allow_local);
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
        Ok(resp) => {
            let status = resp.status();
            fail(
                &format!(
                    "pack upload failed (HTTP {status}){}",
                    response_snippet_suffix(resp)
                ),
                None,
            )
        }
        Err(error) => match *error {
            ureq::Error::Status(code, resp) => fail(
                &format!(
                    "pack upload failed (HTTP {code}){}",
                    response_snippet_suffix(resp)
                ),
                None,
            ),
            ureq::Error::Transport(err) => fail(&format!("pack upload failed: {err}"), None),
        },
    }
}

/// Upload from a held file descriptor without buffering the asset in memory.
/// Each connect retry clones and rewinds the same descriptor; `take(length)`
/// ensures a concurrently extended file can never send bytes beyond the
/// already-validated object length.
pub fn put_presigned_file(cfg: &Config, url: &str, headers: &Value, file: &File, length: u64) {
    let parsed = url::Url::parse(url)
        .unwrap_or_else(|_| fail("the hub returned an invalid upload URL", None));
    let allow_local = presigned_network_policy(cfg, &parsed)
        .unwrap_or_else(|_| fail("the hub returned an unsafe upload URL", None));
    let http = transfer_agent(allow_local);
    let result = with_connect_retries(|| {
        let mut req = http.put(url);
        if let Some(map) = headers.as_object() {
            for (name, value) in map {
                if let Some(value) = value.as_str() {
                    req = req.set(name, value);
                }
            }
        }
        req = req.set("content-length", &length.to_string());
        let mut upload = file.try_clone().unwrap_or_else(|error| {
            fail(
                &format!("asset upload could not clone its stage: {error}"),
                None,
            )
        });
        upload.seek(SeekFrom::Start(0)).unwrap_or_else(|error| {
            fail(
                &format!("asset upload could not rewind its stage: {error}"),
                None,
            )
        });
        req.send(upload.take(length)).map_err(Box::new)
    });
    match result {
        Ok(resp) if resp.status() < 300 => {}
        Ok(resp) => {
            let status = resp.status();
            fail(
                &format!(
                    "asset upload failed (HTTP {status}){}",
                    response_snippet_suffix(resp)
                ),
                None,
            )
        }
        Err(error) => match *error {
            ureq::Error::Status(code, resp) => fail(
                &format!(
                    "asset upload failed (HTTP {code}){}",
                    response_snippet_suffix(resp)
                ),
                None,
            ),
            ureq::Error::Transport(err) => fail(&format!("asset upload failed: {err}"), None),
        },
    }
}

/// `": <body start>"` of an error response, or "" when there is nothing to
/// show. Presigned-storage errors are XML/HTML, and the status code alone
/// ("HTTP 403") hides the actual reason (expiry, signature, clock skew).
fn response_snippet_suffix(resp: ureq::Response) -> String {
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(4096).read_to_end(&mut buf);
    let snippet = snippet_of(&String::from_utf8_lossy(&buf));
    if snippet.is_empty() {
        String::new()
    } else {
        format!(": {snippet}")
    }
}

pub fn get_presigned(cfg: &Config, url: &str, max_bytes: u64) -> Vec<u8> {
    let mut out = Vec::new();
    get_presigned_to_writer(cfg, url, &mut out, max_bytes)
        .unwrap_or_else(|error| fail(&error, None));
    out
}

/// Stream one presigned response into a caller-owned staged writer. The
/// Content-Length header is rejected before reading when it exceeds the cap,
/// and the body loop refuses the first byte past the cap without writing it.
pub fn get_presigned_to_writer<W: Write>(
    cfg: &Config,
    url: &str,
    writer: &mut W,
    max_bytes: u64,
) -> Result<u64, String> {
    let parsed =
        url::Url::parse(url).map_err(|_| "the hub returned an invalid download URL".to_string())?;
    let allow_local = presigned_network_policy(cfg, &parsed)
        .map_err(|_| "the hub returned an unsafe download URL".to_string())?;
    let http = transfer_agent(allow_local);
    let resp = match with_connect_retries(|| http.get(url).call().map_err(Box::new)) {
        Ok(resp) => resp,
        Err(error) => {
            return Err(match *error {
                ureq::Error::Status(code, resp) => format!(
                    "presigned download failed (HTTP {code}){}",
                    response_snippet_suffix(resp)
                ),
                ureq::Error::Transport(err) => format!("presigned download failed: {err}"),
            })
        }
    };
    if let Some(length) = resp.header("content-length") {
        let length = length
            .parse::<u64>()
            .map_err(|_| "presigned download returned an invalid Content-Length".to_string())?;
        if length > max_bytes {
            return Err("presigned download exceeded the supported size".into());
        }
    }
    let mut reader = resp.into_reader();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining_with_probe = max_bytes.saturating_sub(total).saturating_add(1);
        let read_cap = usize::try_from(remaining_with_probe)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let count = reader
            .read(&mut buffer[..read_cap])
            .map_err(|error| format!("presigned download failed mid-body: {error}"))?;
        if count == 0 {
            break;
        }
        let next = total.saturating_add(count as u64);
        if next > max_bytes {
            return Err("presigned download exceeded the supported size".into());
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|error| format!("writing the staged download failed: {error}"))?;
        total = next;
    }
    Ok(total)
}

/// The one not-logged-in message (also used by `secrets set` to refuse BEFORE
/// prompting for a value it could never send).
pub const NOT_LOGGED_IN: &str =
    "not logged in — run `sevra login` (approve in the browser; `--key sevra_account_…` also works)";

pub struct HubResponse {
    pub status: u16,
    pub body: Option<Value>,
    /// The first ~200 chars of the response text (control chars flattened) —
    /// surfaced on errors that carry no JSON `error`, so a proxy page or an
    /// HTML answer is debuggable instead of an opaque "unknown error".
    pub snippet: String,
}

/// The first ~200 chars of a body, printable on one line.
fn snippet_of(text: &str) -> String {
    text.chars()
        .take(200)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
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
/// false only for the login probe / device flow, which supply their own
/// credential inline or none). A transport failure or a mid-body read failure
/// aborts the process — the right default for a one-shot command.
pub fn request(
    cfg: &Config,
    method: &str,
    path: &str,
    body: Option<&Value>,
    auth: bool,
) -> HubResponse {
    match request_inner(cfg, method, path, body, auth, None) {
        Ok(resp) => resp,
        Err(t) => fail(&format!("hub unreachable at {}: {}", cfg.hub, t), None),
    }
}

/// Like `request`, but returns a transport/read failure as `Err(message)`
/// instead of aborting. The device sign-in poll uses this so a brief network
/// blip mid-wait is retried, not fatal — a ten-minute approval window must
/// survive a wifi renegotiation.
pub fn try_request(
    cfg: &Config,
    method: &str,
    path: &str,
    body: Option<&Value>,
    auth: bool,
) -> Result<HubResponse, String> {
    request_inner(cfg, method, path, body, auth, None)
}

/// A hub request with a verb-specific total deadline. Pack commit performs
/// server-side unpack, validation, indexing, and durable publication under a
/// 300-second route budget, so the ordinary 120-second read window is too
/// short even while the server is making healthy progress.
pub fn request_with_timeout(
    cfg: &Config,
    method: &str,
    path: &str,
    body: Option<&Value>,
    auth: bool,
    timeout: std::time::Duration,
) -> HubResponse {
    match request_inner(cfg, method, path, body, auth, Some(timeout)) {
        Ok(resp) => resp,
        Err(t) => fail(&format!("hub unreachable at {}: {}", cfg.hub, t), None),
    }
}

fn request_inner(
    cfg: &Config,
    method: &str,
    path: &str,
    body: Option<&Value>,
    auth: bool,
    timeout: Option<std::time::Duration>,
) -> Result<HubResponse, String> {
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
        if let Some(timeout) = timeout {
            req = req.timeout(timeout);
        }
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

    let resp = match result {
        Ok(resp) => resp,
        Err(error) => match *error {
            ureq::Error::Status(code, resp) => {
                // An HTTP status IS a hub answer — never a transport failure.
                return finish_response(cfg, code, resp);
            }
            ureq::Error::Transport(t) => return Err(t.to_string()),
        },
    };
    let status = resp.status();
    finish_response(cfg, status, resp)
}

fn finish_response(cfg: &Config, status: u16, resp: ureq::Response) -> Result<HubResponse, String> {
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
        return Err(format!("reading the hub's response failed mid-body: {e}"));
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
    Ok(HubResponse {
        status,
        body: parsed,
        snippet: snippet_of(&text),
    })
}

/// The best available error text from a hub answer: the body's `error` (plus
/// its `code` when present), else "unknown error" with the start of whatever
/// the body actually was — never an unexplained "unknown error" over a body
/// that said something.
pub fn hub_error_message(r: &HubResponse) -> String {
    let error = r
        .body
        .as_ref()
        .and_then(|b| b.get("error"))
        .and_then(|e| e.as_str());
    let code = r
        .body
        .as_ref()
        .and_then(|b| b.get("code"))
        .and_then(|c| c.as_str());
    match (error, code) {
        (Some(error), Some(code)) => format!("{error} (code: {code})"),
        (Some(error), None) => error.to_string(),
        (None, _) if r.snippet.is_empty() => "unknown error".to_string(),
        (None, _) => format!("unknown error — body starts: {}", r.snippet),
    }
}

/// Unwrap a successful JSON body, or fail. A >=400 surfaces the hub's own
/// `error`; a 2xx without JSON (captive portal, wrong URL, proxy) is refused
/// here rather than deserializing into nothing downstream.
pub fn ensure_ok(r: HubResponse, what: &str) -> Value {
    if r.status >= 400 {
        let msg = hub_error_message(&r);
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

    #[test]
    fn request_specific_timeout_overrides_the_agent_read_window() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_bytes = [0_u8; 1024];
            let _ = stream.read(&mut request_bytes).unwrap();
            thread::sleep(Duration::from_millis(150));
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
            );
        });
        let cfg = Config {
            hub: format!("http://{address}"),
            key: None,
        };

        let result = request_inner(
            &cfg,
            "GET",
            "/slow",
            None,
            false,
            Some(Duration::from_millis(40)),
        );
        assert!(
            result.is_err(),
            "the request-level deadline must be honored"
        );
        server.join().unwrap();
    }

    #[test]
    fn presigned_download_accepts_u64_max_without_overflow() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_bytes = [0_u8; 1024];
            let _ = stream.read(&mut request_bytes).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });

        let cfg = Config {
            hub: format!("http://{address}"),
            key: None,
        };
        assert_eq!(
            get_presigned(&cfg, &format!("http://{address}/blob"), u64::MAX),
            b"ok"
        );
        server.join().unwrap();
    }

    #[test]
    fn presigned_download_rejects_oversize_content_length_before_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_bytes = [0_u8; 1024];
            let _ = stream.read(&mut request_bytes).unwrap();
            // No body is sent. A bounded client rejects from the header and
            // cannot block waiting for or allocate the declared bytes.
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2147483649\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let cfg = Config {
            hub: format!("http://{address}"),
            key: None,
        };
        let mut staged = Vec::new();
        let error = get_presigned_to_writer(
            &cfg,
            &format!("http://{address}/blob"),
            &mut staged,
            2 * 1024 * 1024 * 1024,
        )
        .unwrap_err();
        assert!(error.contains("exceeded the supported size"));
        assert!(staged.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn remote_hub_cannot_steer_presigned_traffic_to_private_networks() {
        let cfg = Config {
            hub: "https://www.sevrahq.com".into(),
            key: None,
        };
        for hostile in [
            "http://127.0.0.1:3000/admin",
            "https://127.0.0.1/admin",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.1/internal",
            "https://[::1]/admin",
            "https://[fe80::1]/internal",
            "https://[fc00::1]/internal",
        ] {
            let parsed = url::Url::parse(hostile).unwrap();
            assert!(
                presigned_network_policy(&cfg, &parsed).is_err(),
                "remote hub must not approve {hostile}"
            );
        }
    }

    #[test]
    fn only_a_loopback_hub_gets_the_loopback_transfer_exemption() {
        let local_cfg = Config {
            hub: "http://127.0.0.1:3000".into(),
            key: None,
        };
        let local_blob = url::Url::parse("http://127.0.0.1:9000/blob").unwrap();
        assert_eq!(presigned_network_policy(&local_cfg, &local_blob), Ok(true));

        let public_blob = url::Url::parse("https://example.com/blob").unwrap();
        assert_eq!(
            presigned_network_policy(&local_cfg, &public_blob),
            Ok(false)
        );
    }

    #[test]
    fn transfer_ip_policy_rejects_metadata_private_and_mapped_addresses() {
        for private in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "198.18.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !public_transfer_ip(private.parse().unwrap()),
                "{private} must not be reachable through a presigned URL"
            );
        }
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(
                public_transfer_ip(public.parse().unwrap()),
                "{public} should remain a valid public transfer address"
            );
        }
    }
}
