//! The command handlers — full parity with the retired TS CLI, including the
//! quality-pass behaviors (env-blind login, https-only hubs, non-JSON refusal,
//! symlink-contained bounded push, export path containment + slug
//! validation, gated-page reporting). `validate` shells `dbmd` and never links
//! its library — Sevra's product tool consumes the standard through the same
//! public binary any third party gets.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{self, Config, DEFAULT_HUB};
use crate::hub::{
    ensure_ok, get_presigned, put_presigned, request, request_with_timeout, HubResponse,
    NOT_LOGGED_IN,
};
use crate::local;
use crate::output::{fail, json_mode, note, out, usage_fail};
use crate::scan::{redact_path, scan_store, SecretHit};
use crate::store::{build_pack, read_store, read_store_unscoped, Store, StoreError, WalkStats};

/// The hub's poll cadence when it does not say otherwise (it always does).
const POLL_INTERVAL_SECS: u64 = 5;

const MAX_JSON_PUSH_BYTES: usize = 4 * 1024 * 1024;
const MAX_STORE_FILES: usize = 100_000;
const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACK_BYTES: u64 = 256 * 1024 * 1024;
const PACK_COMMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(330);
/// The hub's cap on one secret value (mirrored client-side so an oversized
/// paste fails fast, before any request).
const MAX_SECRET_VALUE_CHARS: usize = 4096;
/// Four UTF-8 bytes per allowed scalar plus one optional CRLF. Piped input is
/// bounded before UTF-8 decoding so a hostile producer cannot grow memory
/// without limit before the character-count check runs.
const MAX_SECRET_STDIN_BYTES: usize = MAX_SECRET_VALUE_CHARS * 4 + 2;

pub(crate) fn enc(s: &str) -> String {
    // Percent-encode a path segment for a URL (RFC 3986 unreserved kept).
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

// --- login / logout / whoami -------------------------------------------------

/// Revoke the session this machine is replacing, best-effort. Overwriting the
/// config drops its key_id, and without this the displaced session stays live
/// on the account forever — unrevokable, since nothing on disk points to it
/// any more — quietly eating one of the ten credential slots on every repeat
/// login. Only OUR sessions carry a key_id, so a user-supplied --key is never
/// touched.
fn revoke_displaced_session(hub: &str) {
    let file = config::load_file();
    let (Some(old_key), Some(_)) = (file.key.as_deref(), file.key_id.as_deref()) else {
        return;
    };
    let old_hub = file.hub.clone().unwrap_or_else(|| hub.to_string());
    let safe = (old_hub.starts_with("https://") || old_hub.starts_with("http://127.0.0.1"))
        && !old_key.is_empty()
        && old_key.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if !safe {
        return;
    }
    let cfg = Config {
        hub: old_hub,
        key: Some(old_key.to_string()),
    };
    let _ = crate::hub::try_request(&cfg, "POST", "/api/hub/keys/revoke-self", None, true);
}

pub fn login(flag_hub: Option<String>, key: Option<String>, no_browser: bool) {
    // Env-blind: login PERSISTS a hub, so a one-off SEVRA_HUB_URL must not
    // silently become the stored default. --hub is the explicit path.
    let hub = flag_hub
        .clone()
        .or(config::load_file().hub)
        .unwrap_or_else(|| DEFAULT_HUB.to_string());
    let hub = hub.strip_suffix('/').unwrap_or(&hub).to_string();
    // The apex 308s to www, and redirects strip the authorization header (the
    // safe default), so a valid key probed against the apex reads back as a
    // misleading 401. Normalize the one known apex to the canonical host.
    let hub = if hub == "https://sevrahq.com" {
        note("note: sevrahq.com redirects to www.sevrahq.com; storing the www host");
        DEFAULT_HUB.to_string()
    } else {
        hub
    };
    if flag_hub.is_none() {
        if let Some(env_hub) = config::env_nonempty("SEVRA_HUB_URL") {
            if env_hub.strip_suffix('/').unwrap_or(&env_hub) != hub {
                note(&format!("note: SEVRA_HUB_URL is ignored by login — pass --hub {env_hub} to store that hub"));
            }
        }
    }
    // --key wins and SEVRA_API_KEY stays the scripted fallback.
    if let Some(k) = key.or_else(|| config::env_nonempty("SEVRA_API_KEY")) {
        // A supplied key: verify it against /me, then persist. No key_id is
        // stored — this credential is the user's, so `logout` must never
        // revoke it server-side.
        let key = crate::hub::clean_key(&k);
        let probe_cfg = Config {
            hub: hub.clone(),
            key: Some(key.clone()),
        };
        let probe = request(&probe_cfg, "GET", "/api/hub/me", None, true);
        let email = probe
            .body
            .as_ref()
            .and_then(|b| b.get("email"))
            .and_then(|e| e.as_str())
            .map(String::from);
        if probe.status != 200 || email.is_none() {
            let suffix = if probe.body.is_none() {
                ", non-JSON response"
            } else {
                ""
            };
            fail(
                &format!(
                    "that key did not authenticate against {hub} (HTTP {}{suffix})",
                    probe.status
                ),
                None,
            );
        }
        revoke_displaced_session(&hub);
        if let Err(e) = config::save(&hub, &key, None) {
            fail(&format!("could not write config: {e}"), None);
        }
        let mut data = probe
            .body
            .and_then(|b| b.as_object().cloned())
            .unwrap_or_default();
        data.insert("hub".into(), json!(hub));
        out(
            &format!(
                "logged in to {hub} as {} (config: {})",
                email.unwrap(),
                config::config_path().display()
            ),
            Some(Value::Object(data)),
        );
        return;
    }

    // No key: sign in through the browser. The loopback flow is the automatic
    // path (nothing to read or type); if this machine can't do it — no
    // browser, no local port — fall back to the code flow, which is the one
    // that works over SSH or from another computer.
    //
    // Either way the hub already proved the account binding and returned the
    // email, so we do NOT re-probe /me: a probe blip must never strand a
    // session the hub just minted.
    let signed_in = if no_browser {
        device_flow_key(&hub)
    } else {
        match browser_flow(&hub) {
            Some(signed_in) => signed_in,
            None => {
                note("no browser available here — falling back to a sign-in code");
                device_flow_key(&hub)
            }
        }
    };
    revoke_displaced_session(&hub);
    if let Err(e) = config::save(&hub, &signed_in.key, Some(&signed_in.key_id)) {
        fail(&format!("could not write config: {e}"), None);
    }
    let who = if signed_in.email.is_empty() {
        "your account".to_string()
    } else {
        signed_in.email.clone()
    };
    out(
        &format!(
            "logged in to {hub} as {who} (config: {})",
            config::config_path().display()
        ),
        Some(json!({ "email": signed_in.email, "hub": hub, "keyId": signed_in.key_id })),
    );
}

struct DeviceLogin {
    key: String,
    email: String,
    key_id: String,
}

/// Random URL-safe token from OS entropy (the PKCE verifier is a credential).
fn random_b64url(bytes: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        fail("could not read secure randomness from the OS", None);
    }
    URL_SAFE_NO_PAD.encode(buf)
}

fn challenge_of(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Hand a URL to the platform's browser. Err means we could not even spawn an
/// opener (headless box, no DE, locked-down Windows) — the caller then falls
/// back to the code flow rather than leaving the human staring at nothing.
///
/// SAFETY: callers pass a URL this process BUILT from the validated hub, never
/// one echoed back by the hub. Windows launches Explorer directly rather than
/// routing the URL through `cmd /C start`, so shell metacharacters are never
/// interpreted. `open`/`xdg-open` receive a parsed HTTPS URL that cannot begin
/// with an option or switch schemes.
fn open_browser(url: &str) -> Result<(), String> {
    let parsed =
        url::Url::parse(url).map_err(|_| "refusing to open an invalid browser URL".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("refusing to open a non-https or unsafe URL".into());
    }
    let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "windows") {
        ("explorer.exe", vec![url])
    } else {
        ("xdg-open", vec![url])
    };
    match Command::new(program)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

const LOOPBACK_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Signed in</title>\
<style>body{font-family:ui-sans-serif,system-ui,sans-serif;background:#f4f3ee;color:#020617;\
display:grid;place-items:center;height:100vh;margin:0}div{text-align:center}\
p{color:#64748b;font-size:14px}</style>\
<div><h2>You're signed in.</h2><p>Return to your terminal. You can close this tab.</p></div>";

/// The automatic sign-in: bind a loopback port, send the human to the hub to
/// approve, and collect the session when the browser is handed back to us.
/// Returns None when this machine can't do it (no listener, no browser), so
/// the caller can fall back to the code flow.
fn browser_flow(hub: &str) -> Option<DeviceLogin> {
    use std::io::Write;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    let cfg = Config {
        hub: hub.to_string(),
        key: None,
    };
    let verifier = random_b64url(32);
    let body = json!({
        "challenge": challenge_of(&verifier),
        "port": port,
        "client": machine_label(),
    });
    let started = ensure_ok(
        request(&cfg, "POST", "/api/hub/auth/cli/start", Some(&body), false),
        "starting sign-in",
    );
    let request_id = str_field(&started, "requestId").to_string();
    // Build the URL OURSELVES from the already-validated hub plus a strictly
    // checked id. The hub's own `approveUrl` is never opened: it would be
    // remote text reaching a process spawner (on Windows, cmd's parser), which
    // is a command-injection surface no amount of escaping makes comfortable.
    if request_id.is_empty() || !request_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let approve_url = format!("{hub}/device?request={request_id}");
    let expires_in = started
        .get("expiresIn")
        .and_then(|v| v.as_u64())
        .unwrap_or(600)
        .clamp(60, 1800);

    // Arm the listener BEFORE opening the browser: if we cannot, we must fall
    // back without having already sent the human to an approval page.
    if listener.set_nonblocking(true).is_err() {
        return None;
    }
    if open_browser(&approve_url).is_err() {
        return None; // headless: the caller falls back to the code flow
    }
    if json_mode() {
        println!(
            "{}",
            json!({
                "status": "awaiting_approval",
                "method": "browser",
                "approveUrl": approve_url,
                "expiresIn": expires_in,
            })
        );
    } else {
        println!("Approve this sign-in in your browser:");
        println!("  {approve_url}");
        println!("Waiting…");
    }

    // Wait for the browser to hand us the authorization code. Non-blocking
    // accept so the wait is bounded by the approval window, and a read timeout
    // on each connection so a socket that never speaks cannot park us forever
    // (browsers speculatively preconnect to loopback and send nothing).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    let mut auth_code: Option<String> = None;
    while std::time::Instant::now() < deadline && auth_code.is_none() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).ok();
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                // Read until we have the whole request line; a single read can
                // split it ("GET /c") and drop the callback on the floor.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(2).any(|w| w == b"\r\n") && buf.len() < 8192 {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let line = head.lines().next().unwrap_or("");
                // Only a callback CARRYING THE CODE counts. A bare probe (or a
                // local process poking the port) gets a 404 and we keep
                // waiting for the real redirect.
                let code = line
                    .strip_prefix("GET /cb?")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|q| {
                        q.split('&')
                            .find_map(|p| p.strip_prefix("code="))
                            .map(str::to_string)
                    })
                    .filter(|c| {
                        !c.is_empty()
                            && c.chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                    });
                if let Some(code) = code {
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            LOOPBACK_PAGE.len(),
                            LOOPBACK_PAGE
                        )
                        .as_bytes(),
                    );
                    auth_code = Some(code);
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    );
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(_) => break,
        }
    }
    let Some(auth_code) = auth_code else {
        fail(
            "the browser never came back — approve in the browser, or run `sevra login --no-browser` to use a code instead",
            None,
        )
    };

    // Two proofs, both required: the verifier (we started this) and the code
    // (the browser handed it to US, on this machine).
    let mut wait_secs = 1;
    for attempt in 0..8 {
        let resp = match crate::hub::try_request(
            &cfg,
            "POST",
            "/api/hub/auth/cli/exchange",
            Some(&json!({
                "requestId": request_id,
                "verifier": verifier,
                "code": auth_code,
            })),
            false,
        ) {
            Ok(resp) => resp,
            Err(t) if attempt == 7 => fail(
                &format!("could not reach the hub to finish sign-in: {t}"),
                None,
            ),
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_secs(wait_secs));
                wait_secs = (wait_secs * 2).min(8);
                continue;
            }
        };
        let body = resp.body.clone().unwrap_or(Value::Null);
        match (resp.status, str_field(&body, "status")) {
            (200, "approved") => {
                let key = crate::hub::clean_key(str_field(&body, "key"));
                if key.is_empty() {
                    fail(
                        "the hub approved the sign-in but sent no key — try again",
                        None,
                    );
                }
                return Some(DeviceLogin {
                    key,
                    email: str_field(&body, "email").to_string(),
                    key_id: str_field(&body, "keyId").to_string(),
                });
            }
            (200, "pending") => std::thread::sleep(std::time::Duration::from_secs(1)),
            (200, "denied") => fail("the sign-in was denied in the browser", None),
            (200, "failed") => fail(
                &format!(
                    "the hub could not finish sign-in: {}",
                    str_field(&body, "error")
                ),
                None,
            ),
            // Throttling and hub trouble are transient, not "unrecognized" —
            // back off and keep trying rather than killing a live sign-in.
            (429, _) | (500..=599, _) => {
                std::thread::sleep(std::time::Duration::from_secs(wait_secs));
                wait_secs = (wait_secs * 2).min(8);
            }
            _ => fail(
                "the hub no longer recognizes this sign-in — run `sevra login` again",
                None,
            ),
        }
    }
    fail("sign-in did not complete — run `sevra login` again", None);
}

/// The approve-in-browser sign-in (`sevra login` with no key): start a device
/// authorization, show the human the code + URL, poll until the hub hands
/// back a fresh account key. The device code never leaves this process; the
/// human types nothing but a click.
///
/// Agent contract for `--json`: the FIRST stdout line is a compact JSON
/// `awaiting_approval` event (relay its URL + code); the FINAL stdout value is
/// the pretty-printed login object. Read line 1 as an event, then parse the
/// remainder as one object.
fn device_flow_key(hub: &str) -> DeviceLogin {
    let cfg = Config {
        hub: hub.to_string(),
        key: None,
    };
    let body = match machine_label() {
        Some(name) => json!({ "client": name }),
        None => json!({}),
    };
    let started = ensure_ok(
        request(&cfg, "POST", "/api/hub/auth/device", Some(&body), false),
        "starting sign-in",
    );
    let device_code = str_field(&started, "deviceCode").to_string();
    let user_code = str_field(&started, "userCode").to_string();
    if device_code.is_empty() || user_code.is_empty() {
        fail(
            "the hub's sign-in answer was missing the codes — is this a Sevra hub? (`sevra login --key …` still works)",
            None,
        );
    }
    let verify_at = {
        let complete = str_field(&started, "verificationUriComplete");
        if complete.is_empty() {
            format!("{hub}/device")
        } else {
            complete.to_string()
        }
    };
    // Clamp the hub-supplied timings: a remote value must never make the CLI
    // busy-loop (interval 0), sleep for a day (interval huge), overflow the
    // deadline (expiresIn near u64::MAX), or give up before the first poll
    // (expiresIn <= interval).
    let interval = started
        .get("interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(POLL_INTERVAL_SECS)
        .clamp(1, 60);
    let expires_in = started
        .get("expiresIn")
        .and_then(|v| v.as_u64())
        .unwrap_or(900)
        .clamp(interval + 30, 1800);

    if json_mode() {
        println!(
            "{}",
            json!({
                "status": "awaiting_approval",
                "userCode": user_code,
                "verificationUri": str_field(&started, "verificationUri"),
                "verificationUriComplete": verify_at,
                "expiresIn": expires_in,
                "interval": interval,
            })
        );
    } else {
        println!("First, confirm this code in your browser: {user_code}");
        println!("Open: {verify_at}");
        println!("Waiting for approval…");
    }

    // Backoff grows the gap on throttle or trouble, capped, and never below the
    // hub's interval; the whole loop is bounded by the deadline.
    // clamp() ASSERTS min <= max, so the floor must never exceed the ceiling:
    // interval is allowed up to 60, and a hub sending 45 would otherwise panic
    // the process on the first 429 or 5xx — the clamp block exists precisely
    // to survive hostile timings, so it must not be the thing that crashes.
    let ceiling = interval.max(30);
    let backoff = move |w: u64| w.saturating_mul(2).clamp(interval, ceiling);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    let mut wait = interval;
    let mut last_trouble: Option<String> = None;
    loop {
        if std::time::Instant::now() >= deadline {
            match last_trouble {
                Some(t) => fail(
                    &format!("sign-in did not complete — the hub had trouble ({t}). Run `sevra login` again."),
                    None,
                ),
                None => fail("the approval window closed — run `sevra login` again", None),
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(wait));
        // try_request, not request: a transport blip mid-wait must be retried,
        // not fatal.
        let resp = match crate::hub::try_request(
            &cfg,
            "POST",
            "/api/hub/auth/device/token",
            Some(&json!({ "deviceCode": device_code })),
            false,
        ) {
            Ok(resp) => resp,
            Err(t) => {
                last_trouble = Some(t);
                wait = backoff(wait);
                continue;
            }
        };
        match resp.status {
            200 => {
                let body = resp.body.unwrap_or(Value::Null);
                match str_field(&body, "status") {
                    "pending" => {
                        wait = interval;
                        last_trouble = None;
                    }
                    "approved" => {
                        let key = crate::hub::clean_key(str_field(&body, "key"));
                        if key.is_empty() {
                            fail(
                                "the hub approved the sign-in but sent no key — try again",
                                None,
                            );
                        }
                        return DeviceLogin {
                            key,
                            email: str_field(&body, "email").to_string(),
                            key_id: str_field(&body, "keyId").to_string(),
                        };
                    }
                    "denied" => fail("the sign-in was denied in the dashboard", None),
                    "failed" => {
                        // The hub's own message only — never echo its whole
                        // body to stdout on a credential path.
                        let msg = str_field(&body, "error");
                        fail(&format!("the hub could not finish sign-in: {msg}"), None)
                    }
                    other => fail(
                        &format!("unexpected sign-in state from the hub: {other:?}"),
                        None,
                    ),
                }
            }
            // Throttled: grow the gap. Repeated 429s back off further, so the
            // client self-adjusts to whatever pace the hub wants.
            429 => wait = backoff(wait),
            400 => {
                let code = resp
                    .body
                    .as_ref()
                    .and_then(|b| b.get("code"))
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                if code == "expired" {
                    fail("the code expired — run `sevra login` again", None);
                }
                fail(
                    "the hub no longer recognizes this sign-in — run `sevra login` again",
                    None,
                );
            }
            // A transient hub error must not kill the wait: back off and keep
            // trying until the deadline (not a fixed retry count).
            s if s >= 500 => {
                last_trouble = Some(format!("HTTP {s}"));
                wait = backoff(wait);
            }
            s => fail(
                &format!("unexpected hub answer during sign-in (HTTP {s})"),
                None,
            ),
        }
    }
}

/// A cosmetic label for the approval page + the minted key's name. `hostname`
/// exists on every target OS; anything odd just means no label.
fn machine_label() -> Option<String> {
    let out = Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub fn logout() {
    // Revoke a browser-minted key server-side first (best-effort): device
    // sign-ins each mint a fresh key, so without this they pile up unrevoked
    // against the account cap. Only keys WE minted carry a key_id; a
    // user-supplied `--key` has none and is left alone (they may use it
    // elsewhere). A network failure here must never block the local logout.
    let file = config::load_file();
    if let (Some(key), Some(_id)) = (file.key.as_deref(), file.key_id.as_deref()) {
        let hub = file
            .hub
            .clone()
            .unwrap_or_else(|| config::DEFAULT_HUB.to_string());
        // Pre-check what the hub client would otherwise ABORT the process over
        // (a non-HTTPS stored hub, a key with stray bytes). try_request routes
        // those through fail(), which would exit before we ever remove the
        // credential file — the exact situation where removing it matters most.
        let safe_hub = hub.starts_with("https://") || hub.starts_with("http://127.0.0.1");
        let safe_key = !key.is_empty() && key.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if safe_hub && safe_key {
            let cfg = Config {
                hub,
                key: Some(key.to_string()),
            };
            // auth:true sends the very key we are revoking as the bearer — the
            // hub revokes exactly the presented credential.
            let confirmed = matches!(
                crate::hub::try_request(&cfg, "POST", "/api/hub/keys/revoke-self", None, true),
                Ok(r) if r.status == 200
                    && r.body.as_ref().and_then(|b| b.get("revoked")).and_then(|v| v.as_bool()) == Some(true)
            );
            // Never silently claim a clean logout: the key is about to leave
            // this machine, so the human needs to know if it is still live.
            if !confirmed {
                note("could not confirm the sign-in was revoked on the hub — revoke it under Account → Sign-ins");
            }
        } else {
            note("skipped the server-side revoke (stored hub or key looks malformed) — revoke under Account → Sign-ins");
        }
    }

    // Honest about what happened: a credential file that EXISTS but cannot be
    // removed must be a loud failure (the key would silently survive on disk),
    // and a no-op logout must not claim it removed anything.
    match config::remove() {
        Ok(true) => out(
            "logged out (removed ~/.sevra/config.json)",
            Some(json!({ "ok": true, "removed": true })),
        ),
        Ok(false) => out(
            "logged out (no stored credential to remove)",
            Some(json!({ "ok": true, "removed": false })),
        ),
        Err(e) => fail(
            &format!(
                "could not remove {} — the stored key is STILL on disk: {e}",
                config::config_path().display()
            ),
            None,
        ),
    }
}

pub fn whoami(cfg: &Config) {
    let me = ensure_ok(request(cfg, "GET", "/api/hub/me", None, true), "whoami");
    out(
        &format!(
            "{} ({}) @ {}",
            str_field(&me, "email"),
            str_field(&me, "userId"),
            cfg.hub
        ),
        Some(me),
    );
}

// --- brains ------------------------------------------------------------------

pub fn brains(cfg: &Config) {
    let r = ensure_ok(
        request(cfg, "GET", "/api/hub/brains", None, true),
        "list brains",
    );
    let list = r
        .get("brains")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    if json_mode() {
        out("", Some(json!({ "brains": list })));
        return;
    }
    if list.is_empty() {
        out("no brains yet — `sevra create <slug>`", None);
        return;
    }
    for b in list {
        out(
            &format!(
                "{}\t{}\t{}\t{}",
                str_field(&b, "slug"),
                str_field(&b, "id"),
                str_field(&b, "visibility"),
                str_field(&b, "name")
            ),
            None,
        );
    }
}

pub fn create(cfg: &Config, slug: &str, name: Option<String>, scope: Option<String>, public: bool) {
    let body = json!({
        "slug": slug,
        "name": name,
        "scope": scope,
        "visibility": if public { "public" } else { "private" },
    });
    let b = ensure_ok(
        request(cfg, "POST", "/api/hub/brains", Some(&body), true),
        "create brain",
    );
    out(
        &format!(
            "created brain {} ({}, {})",
            str_field(&b, "slug"),
            str_field(&b, "id"),
            str_field(&b, "visibility")
        ),
        Some(b),
    );
}

/// Interactive confirmation for `delete`: show what dies, require the slug
/// typed back. Scripted callers (no TTY, or --json) must pass --confirm.
fn prompt_delete_confirmation(cfg: &Config, brain: &str) -> String {
    use std::io::IsTerminal;
    if json_mode() || !std::io::stdin().is_terminal() {
        fail(
            "deleting a brain is permanent and needs confirmation — rerun with --confirm <slug> (the brain's exact slug; `sevra brains` lists them)",
            None,
        );
    }
    // Show what will be deleted — and learn the slug the hub will demand,
    // so an id-referenced delete still confirms against the right word.
    let r = ensure_ok(request(cfg, "GET", "/api/hub/brains", None, true), "delete");
    let list = r
        .get("brains")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    let Some(b) = list
        .iter()
        .find(|b| str_field(b, "slug") == brain || str_field(b, "id") == brain)
    else {
        fail(
            &format!("no brain '{brain}' in your account — `sevra brains` lists yours"),
            None,
        )
    };
    let slug = str_field(b, "slug").to_string();
    let name = str_field(b, "name");
    let label = if name.is_empty() || name == slug {
        format!("'{slug}'")
    } else {
        format!("'{slug}' ({name})")
    };
    eprintln!(
        "This permanently deletes {label} from the hub — every hosted file, its index, published pages, and grants. There is no undo."
    );
    eprint!("type the brain's slug to confirm: ");
    let mut typed = String::new();
    if std::io::stdin().read_line(&mut typed).is_err() {
        fail(
            "could not read the confirmation — nothing was deleted",
            None,
        );
    }
    let typed = typed.trim();
    if typed != slug {
        fail(
            &format!("confirmation did not match the slug '{slug}' — nothing was deleted"),
            None,
        );
    }
    typed.to_string()
}

pub fn delete(cfg: &Config, brain: &str, confirm: Option<String>) {
    let confirm = confirm.unwrap_or_else(|| prompt_delete_confirmation(cfg, brain));
    let resp = request(
        cfg,
        "DELETE",
        &format!("/api/hub/brains/{}", enc(brain)),
        Some(&json!({ "confirm": confirm })),
        true,
    );
    // The hub's own guard: a missing or mismatched confirm answers 400
    // confirm_required. Map it to the action that unblocks.
    if resp.status == 400 && body_code(&resp) == Some("confirm_required") {
        let server = resp
            .body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("the hub requires the brain's slug to confirm")
            .to_string();
        fail(
            &format!(
                "delete refused (HTTP 400): {server}\nconfirm with the brain's exact slug: sevra delete {brain} --confirm <slug> (`sevra brains` lists slugs)"
            ),
            resp.body,
        );
    }
    let r = ensure_ok(resp, "delete");
    let objects = r.get("r2Objects").and_then(|v| v.as_i64()).unwrap_or(0);
    out(
        &format!("deleted {brain} permanently ({objects} hosted object(s) removed)"),
        Some(r),
    );
}

// --- push --------------------------------------------------------------------

/// Bytes for humans, in the binary units the hub's limits are defined in.
pub(crate) fn human_size(bytes: u64) -> String {
    const K: f64 = 1024.0;
    let b = bytes as f64;
    if b >= K * K * K {
        format!("{:.1} GiB", b / (K * K * K))
    } else if b >= K * K {
        format!("{:.1} MiB", b / (K * K))
    } else if b >= K {
        format!("{:.1} KiB", b / K)
    } else {
        format!("{bytes} B")
    }
}

/// 100000 → "100,000" — counts read at a glance in refusal messages.
fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    grouped
}

/// Refuse, locally, a push the hub's snapshot limits would reject anyway —
/// before a single byte is uploaded — naming the limit, the actual numbers,
/// and the largest files so the operator knows what to trim.
fn fail_snapshot_limit(problem: &str, largest: &[(String, u64)], data: Value) -> ! {
    let mut msg = format!("{problem}\nlargest files:");
    for (path, bytes) in largest {
        msg.push_str(&format!("\n  {:>9}  {path}", human_size(*bytes)));
    }
    msg.push_str(
        "\ntrim what should not ship (sources/ usually holds the bulk); for a deliberately large store, split it across brains and push each part separately",
    );
    let mut data = data;
    if let Some(obj) = data.as_object_mut() {
        obj.insert(
            "largestFiles".into(),
            json!(largest
                .iter()
                .map(|(path, bytes)| json!({ "path": path, "bytes": bytes }))
                .collect::<Vec<_>>()),
        );
    }
    fail(&msg, Some(data));
}

/// How many secret hits a refusal shows before eliding.
const SECRET_HITS_SHOWN: usize = 20;

/// The hit list block shared by push's refusal and `secrets scan`: each hit
/// as `path — kind`, never a matched value (paths that themselves match are
/// already redacted by the scanner), capped at `SECRET_HITS_SHOWN`.
fn secret_hits_block(hits: &[SecretHit]) -> String {
    let mut msg = String::new();
    for hit in hits.iter().take(SECRET_HITS_SHOWN) {
        let place = if hit.in_path {
            " (in the file's name)"
        } else {
            ""
        };
        msg.push_str(&format!("\n  {} — {}{place}", hit.path, hit.kind));
    }
    if hits.len() > SECRET_HITS_SHOWN {
        msg.push_str(&format!(
            "\n  … and {} more",
            hits.len() - SECRET_HITS_SHOWN
        ));
    }
    msg
}

/// The machine half of the same refusal — one shape for push and scan.
fn secret_hits_data(hits: &[SecretHit]) -> Value {
    json!({
        "secretHits": hits
            .iter()
            .take(SECRET_HITS_SHOWN)
            .map(|h| json!({ "path": h.path, "kind": h.kind, "inPath": h.in_path }))
            .collect::<Vec<_>>(),
        "total": hits.len(),
    })
}

/// The push secret-scan refusal, naming the three exits in order: keep the
/// files home, edit them, or ship them anyway.
fn fail_secret_hits(hits: &[SecretHit], dir: &str) -> ! {
    let mut msg = format!(
        "push refused: {} match(es) for known secret formats in the store (matched values are never shown):",
        hits.len()
    );
    msg.push_str(&secret_hits_block(hits));
    msg.push_str(&format!(
        "\nrotate anything that ever lived here; keep live secrets in a password manager and references to them in the brain.\nthree ways out, in order: `sevra secrets quarantine {dir}` (keep these files home) · edit the files yourself · `--allow-secrets` (push them verbatim)"
    ));
    fail(&msg, Some(secret_hits_data(hits)));
}

fn body_code(r: &HubResponse) -> Option<&str> {
    r.body
        .as_ref()
        .and_then(|b| b.get("code"))
        .and_then(|c| c.as_str())
}

/// `ensure_ok` for the push verbs, with the shrink guard mapped: without
/// --force, a 409 `shrink_refused` (the hub protecting a brain from a smaller
/// replacement) prints the hub's message verbatim plus the one hint that
/// unblocks an intended replacement — and, when the walk kept files home,
/// the line that explains part of the difference.
fn ensure_push_ok(r: HubResponse, what: &str, force: bool, kept_home: usize) -> Value {
    if !force && r.status == 409 && body_code(&r) == Some("shrink_refused") {
        let server = r
            .body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("the hub refused to shrink the brain")
            .to_string();
        let mut msg = format!(
            "{what} failed (HTTP 409): {server}\nretry with --force if the replacement is intended"
        );
        if kept_home > 0 {
            msg.push_str(&format!(
                "\n({kept_home} document(s) are kept home by .sevralocal and not part of this push)"
            ));
        }
        fail(&msg, r.body);
    }
    ensure_ok(r, what)
}

/// Commit an uploaded pack. A 507 `hub_scratch_exhausted` means the pack IS
/// uploaded and only the hub's unpack scratch is busy — retry the commit
/// after a pause, never the upload.
fn commit_pack(cfg: &Config, brain: &str, commit: &Value, force: bool, kept_home: usize) -> Value {
    let mut attempt: u64 = 0;
    loop {
        let resp = request_with_timeout(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/packs/commit", enc(brain)),
            Some(commit),
            true,
            PACK_COMMIT_TIMEOUT,
        );
        if resp.status == 507 && body_code(&resp) == Some("hub_scratch_exhausted") && attempt < 2 {
            attempt += 1;
            let pause = 5 * attempt;
            note(&format!(
                "the hub's unpack scratch is busy — the pack is already uploaded; retrying the commit in {pause}s ({attempt}/2)"
            ));
            std::thread::sleep(std::time::Duration::from_secs(pause));
            continue;
        }
        return ensure_push_ok(resp, "commit pack", force, kept_home);
    }
}

/// The shared store read for push, scan, and quarantine — every store error
/// maps to the same refusal push uses. `scoped` reads what a push would
/// carry (`.sevralocal` honored); unscoped is quarantine's full view.
fn read_store_checked(dir: &str, scoped: bool) -> (Store, WalkStats) {
    let result = if scoped {
        read_store(dir, MAX_STORE_BYTES)
    } else {
        read_store_unscoped(dir, MAX_STORE_BYTES)
    };
    match result {
        Ok(pair) => pair,
        Err(StoreError::OverCap(stats)) => fail_snapshot_limit(
            &format!(
                "store is {} uncompressed across {} files — the hub caps one snapshot at {} uncompressed",
                human_size(stats.bytes),
                commas(stats.files as u64),
                human_size(MAX_STORE_BYTES)
            ),
            &stats.largest,
            json!({ "limitBytes": MAX_STORE_BYTES, "storeBytes": stats.bytes, "files": stats.files }),
        ),
        Err(StoreError::Scope(msg)) => fail(&msg, None),
        Err(StoreError::Io(e)) => fail(&format!("could not read {dir}: {e}"), None),
    }
}

pub fn push(
    cfg: &Config,
    dir: &str,
    brain: &str,
    force: bool,
    allow_secrets: bool,
    skip_assets: bool,
) {
    if !Path::new(dir).exists() {
        fail(&format!("store directory not found: {dir}"), None);
    }
    let (store, stats) = read_store_checked(dir, true);
    if store.files.is_empty() {
        let kept = stats.kept_home + stats.catalogs_kept;
        if kept > 0 {
            fail(
                &format!(
                    "no .md files to push under {dir} — all {kept} file(s) are kept home (.sevralocal)"
                ),
                Some(
                    json!({ "keptHome": stats.kept_home, "catalogsKeptHome": stats.catalogs_kept }),
                ),
            );
        }
        fail(&format!("no .md files under {dir}"), None);
    }
    if store.files.len() > MAX_STORE_FILES {
        fail_snapshot_limit(
            &format!(
                "store has {} files — the hub caps one snapshot at {} files",
                commas(store.files.len() as u64),
                commas(MAX_STORE_FILES as u64)
            ),
            &stats.largest,
            json!({ "limitFiles": MAX_STORE_FILES, "files": store.files.len() }),
        );
    }
    // The last gate before bytes leave the machine: refuse secret-shaped
    // content and file names unless the operator explicitly overrides.
    if !allow_secrets {
        let hits = scan_store(&store);
        if !hits.is_empty() {
            fail_secret_hits(&hits, dir);
        }
    }
    let mut payload = serde_json::to_value(&store).unwrap();
    if force {
        payload["allow_shrink"] = json!(true);
    }
    let file_count = store.files.len();
    // Everything the walk kept home — the honest count when the hub's shrink
    // guard asks where the missing documents went.
    let kept_total = stats.kept_home + stats.catalogs_kept;
    let payload_bytes = payload.to_string().len();
    let r = if payload_bytes <= MAX_JSON_PUSH_BYTES {
        ensure_push_ok(
            request(
                cfg,
                "POST",
                &format!("/api/hub/brains/{}/push", enc(brain)),
                Some(&payload),
                true,
            ),
            "push",
            force,
            kept_total,
        )
    } else {
        let pack = build_pack(&store)
            .unwrap_or_else(|e| fail(&format!("could not build store pack: {e}"), None));
        if pack.len() as u64 > MAX_PACK_BYTES {
            fail_snapshot_limit(
                &format!(
                    "compressed store pack is {} — the hub caps one pack at {} compressed",
                    human_size(pack.len() as u64),
                    human_size(MAX_PACK_BYTES)
                ),
                &stats.largest,
                json!({ "limitBytes": MAX_PACK_BYTES, "packBytes": pack.len() }),
            );
        }
        let sha256 = format!("{:x}", Sha256::digest(&pack));
        let meta = json!({ "sha256": sha256, "bytes": pack.len() });
        let presigned = ensure_ok(
            request(
                cfg,
                "POST",
                &format!("/api/hub/brains/{}/packs/presign", enc(brain)),
                Some(&meta),
                true,
            ),
            "prepare pack upload",
        );
        let url = presigned
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("hub returned no pack upload URL", None));
        put_presigned(url, presigned.get("headers").unwrap_or(&Value::Null), &pack);
        let mut commit = meta;
        if force {
            commit["allow_shrink"] = json!(true);
        }
        commit_pack(cfg, brain, &commit, force, kept_total)
    };
    let s = r.get("indexed").cloned().unwrap_or(json!({}));
    let n = |k: &str| s.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    let mut human = format!(
        "pushed {file_count} files → indexed {} docs, {} edges ({} broken), {} assets",
        n("documents"),
        n("edges"),
        n("brokenEdges"),
        n("assets")
    );
    // What stayed home, reported alongside what rode.
    let mut data = r;
    if stats.kept_home > 0 {
        human.push_str(&format!(
            "\n{} file(s) kept home (.sevralocal)",
            stats.kept_home
        ));
        if let Some(obj) = data.as_object_mut() {
            obj.insert("keptHome".into(), json!(stats.kept_home));
        }
    }
    if stats.catalogs_kept > 0 {
        human.push_str(&format!(
            "\n{} derived catalog(s) kept home (the hub rebuilds its own)",
            stats.catalogs_kept
        ));
        if let Some(obj) = data.as_object_mut() {
            obj.insert("catalogsKeptHome".into(), json!(stats.catalogs_kept));
        }
    }

    // The byte half of the asset story: the snapshot just ingested the
    // manifest, so every declared hash is now uploadable — ship what the hub
    // reports missing. Strictly after the commit (the hub refuses undeclared
    // hashes) and skippable for a metadata-only push.
    let manifest_assets = n("assets");
    if !skip_assets && manifest_assets > 0 {
        let scope = crate::local::load(Path::new(dir)).ok().flatten();
        let sync = crate::assets::sync_after_push(cfg, brain, dir, scope.as_ref());
        if sync.uploaded > 0 {
            human.push_str(&format!(
                "\nassets: {} uploaded ({})",
                sync.uploaded,
                human_size(sync.uploaded_bytes)
            ));
        } else if sync.missing_local == 0 && sync.drifted == 0 {
            human.push_str(&format!("\nassets: all {manifest_assets} present"));
        }
        if sync.kept_home > 0 {
            human.push_str(&format!(
                "\nassets: {} kept home (.sevralocal)",
                sync.kept_home
            ));
        }
        if sync.missing_local > 0 || sync.drifted > 0 {
            human.push_str(&format!(
                "\nassets: {} missing locally, {} drifted — run `dbmd assets scan` and push again",
                sync.missing_local, sync.drifted
            ));
        }
        if let Some(obj) = data.as_object_mut() {
            obj.insert("assetSync".into(), sync.to_json());
        }
    }
    out(&human, Some(data));
}

// --- query / get / graph -----------------------------------------------------

/// `query` takes its brain positionally or via `--brain` (the flag `push`
/// uses — the two commands must not disagree). With `--brain` present the
/// first positional is the search text; the belt-and-braces shape
/// `query <brain> <text> --brain <ref>` must agree with the flag.
pub fn resolve_query_target(
    flag: Option<String>,
    first: Option<String>,
    second: Option<String>,
) -> Result<(String, Option<String>), String> {
    match (flag, first, second) {
        (None, Some(brain), text) => Ok((brain, text)),
        // clap fills positionals in order, so second without first cannot occur.
        (None, None, _) => Err(
            "which brain? `sevra query <brain> [text]`, or `sevra query --brain <ref> [text]`"
                .into(),
        ),
        (Some(flag), None, text) => Ok((flag, text)),
        (Some(flag), Some(text), None) => Ok((flag, Some(text))),
        (Some(flag), Some(first), Some(text)) => {
            if first == flag {
                Ok((flag, Some(text)))
            } else {
                Err(format!(
                    "the brain was given twice and differs: '{first}' (positional) vs '{flag}' (--brain) — pass it once"
                ))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn query(
    cfg: &Config,
    brain: &str,
    text: Option<String>,
    type_: Option<String>,
    layer: Option<String>,
    meta_type: Option<String>,
    tag: Option<String>,
    order: Option<String>,
    limit: Option<u32>,
    where_: Option<String>,
) {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(q) = text {
        params.push(("q".into(), q));
    }
    for (k, v) in [
        ("type", type_),
        ("layer", layer),
        ("meta-type", meta_type),
        ("tag", tag),
        ("order", order),
        ("limit", limit.map(|n| n.to_string())),
    ] {
        if let Some(val) = v {
            params.push((k.into(), val));
        }
    }
    if let Some(w) = where_ {
        params.push(("where".into(), w));
    }
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/query?{qs}", enc(brain)),
            None,
            true,
        ),
        "query",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    out(
        &format!(
            "{} result(s):",
            r.get("total").and_then(|t| t.as_i64()).unwrap_or(0)
        ),
        None,
    );
    for d in r
        .get("results")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let sum = d
            .get("summary")
            .and_then(|s| s.as_str())
            .or_else(|| d.get("title").and_then(|t| t.as_str()))
            .unwrap_or("");
        out(
            &format!(
                "  {}\t{}\t{}",
                str_field(&d, "path"),
                str_field(&d, "type"),
                sum
            ),
            None,
        );
    }
}

pub fn get(cfg: &Config, brain: &str, reference: &str) {
    let key = if reference.contains('/') || reference.to_lowercase().ends_with(".md") {
        "path"
    } else {
        "id"
    };
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!(
                "/api/hub/brains/{}/resolve?{key}={}",
                enc(brain),
                enc(reference)
            ),
            None,
            true,
        ),
        "get",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let d = r.get("document").cloned().unwrap_or(json!({}));
    let title = d
        .get("title")
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| str_field(&d, "path"));
    out(
        &format!(
            "# {title}\npath: {}\ntype: {}  meta-type: {}\nid: {}\n\n{}",
            str_field(&d, "path"),
            str_field(&d, "type"),
            str_field(&d, "metaType"),
            str_field(&d, "dbmdId"),
            str_field(&d, "body")
        ),
        None,
    );
}

pub fn graph(cfg: &Config, brain: &str, path: &str, dir: Option<String>) {
    // clap's value_parser already constrained --dir to in|out|both.
    let dir = dir.unwrap_or_else(|| "both".into());
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!(
                "/api/hub/brains/{}/graph?path={}&dir={}",
                enc(brain),
                enc(path),
                enc(&dir)
            ),
            None,
            true,
        ),
        "graph",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let edges = |k: &str| {
        r.get(k)
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
    };
    let back = edges("backlinks");
    out(&format!("backlinks ({}):", back.len()), None);
    for e in back {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) {
            ""
        } else {
            " (broken)"
        };
        out(&format!("  ← {}{broken}", str_field(&e, "srcPath")), None);
    }
    let outl = edges("outlinks");
    out(&format!("outlinks ({}):", outl.len()), None);
    for e in outl {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) {
            ""
        } else {
            " (broken)"
        };
        out(&format!("  → {}{broken}", str_field(&e, "dstPath")), None);
    }
}

// --- grants ------------------------------------------------------------------

pub fn grant(cfg: &Config, brain: &str, email: &str, write: bool) {
    let capability = if write { "write" } else { "read" };
    let body = json!({ "email": email, "capability": capability });
    let r = ensure_ok(
        request(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/grants", enc(brain)),
            Some(&body),
            true,
        ),
        "grant",
    );
    if r.get("pending").and_then(|p| p.as_bool()).unwrap_or(false) {
        out(&format!("invited {email} to {brain} ({capability}) — they get access when they sign up free"), Some(r));
    } else {
        out(
            &format!("granted {capability} on {brain} to {email}"),
            Some(r),
        );
    }
}

pub fn grants(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/grants", enc(brain)),
            None,
            true,
        ),
        "grants",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let list = r
        .get("grants")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        out("no grants", None);
        return;
    }
    for g in list {
        out(
            &format!(
                "  {}\t{}\t{}",
                str_field(&g, "email"),
                str_field(&g, "capability"),
                str_field(&g, "id")
            ),
            None,
        );
    }
}

pub fn revoke(cfg: &Config, brain: &str, grant_id: &str) {
    ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/grants/{}", enc(brain), enc(grant_id)),
            None,
            true,
        ),
        "revoke",
    );
    out(
        &format!("revoked grant {grant_id}"),
        Some(json!({ "revoked": true })),
    );
}

pub fn shared(cfg: &Config) {
    let r = ensure_ok(request(cfg, "GET", "/api/hub/shared", None, true), "shared");
    if json_mode() {
        out("", Some(r));
        return;
    }
    let list = r
        .get("shared")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        out("nothing shared with you", None);
        return;
    }
    for b in list {
        out(
            &format!(
                "  {}\t{}\t{}\t{}",
                str_field(&b, "slug"),
                str_field(&b, "id"),
                str_field(&b, "capability"),
                str_field(&b, "name")
            ),
            None,
        );
    }
}

// --- publish / unpublish / inbox / export ------------------------------------

pub fn publish(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/publish", enc(brain)),
            None,
            true,
        ),
        "publish",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let layout_notes: Vec<String> = r
        .get("layoutErrors")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|e| format!("skipped (layout: site): {}", str_field(e, "message")))
        .collect();
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 {
        for m in &layout_notes {
            out(m, None);
        }
        out("nothing public to publish yet — make the brain public (`sevra` dashboard) or mark records `visibility: public`, then publish again.", None);
        return;
    }
    let url = str_field(&r, "url");
    out(&format!("published {count} page(s) → {url}"), None);
    for p in r
        .get("published")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        out(
            &format!(
                "  {url}/{}\t{}",
                str_field(&p, "pageSlug"),
                str_field(&p, "title")
            ),
            None,
        );
    }
    for m in &layout_notes {
        out(&format!("  {m}"), None);
    }
    let gated = r
        .get("gatedPages")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    if !gated.is_empty() {
        let paths = gated
            .iter()
            .map(|g| str_field(g, "docPath").to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out(&format!("  {} record(s) gated by audience — served behind Sign in with Sevra, never on public surfaces: {paths}", gated.len()), None);
    }
}

pub fn unpublish(cfg: &Config, brain: &str) {
    ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/publish", enc(brain)),
            None,
            true,
        ),
        "unpublish",
    );
    out(
        &format!("unpublished {brain} (public pages pulled)"),
        Some(json!({ "unpublished": true })),
    );
}

pub fn inbox(cfg: &Config, action: &str, brain: &str) {
    // clap's value_parser already constrained the action to list|drain.
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/inbox?limit=200", enc(brain)),
            None,
            true,
        ),
        "inbox",
    );
    if json_mode() || action == "drain" {
        // drain prints the full payload as JSON regardless of mode (the BYO
        // agent's read half).
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
        return;
    }
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 {
        out("inbox empty — no submissions.", None);
        return;
    }
    out(&format!("{count} submission(s):"), None);
    for it in r
        .get("items")
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default()
    {
        out(
            &format!(
                "  {}  {}  {}  {}",
                it.get("created").and_then(|c| c.as_str()).unwrap_or("-"),
                it.get("app").and_then(|a| a.as_str()).unwrap_or("-"),
                str_field(&it, "submittedBy"),
                str_field(&it, "path")
            ),
            None,
        );
    }
}

/// Normalize + contain: the resolved write path must stay inside `root`.
pub(crate) fn contained(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() || rel.contains('\0') {
        return None;
    }
    let mut full = root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => full.push(c),
            _ => return None, // .. / root / prefix — reject outright
        }
    }
    if full == root {
        return None;
    }
    Some(full)
}

fn entries_from_pack(bytes: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .unwrap_or_else(|e| fail(&format!("hub returned an invalid store pack: {e}"), None));
    if archive.is_empty() || archive.len() > 100_000 {
        fail("hub returned a store pack with an invalid file count", None);
    }
    let mut entries = Vec::with_capacity(archive.len());
    let mut seen = std::collections::HashSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .unwrap_or_else(|e| fail(&format!("could not read store pack entry: {e}"), None));
        if file.is_dir() {
            continue;
        }
        let path = file.name().to_string();
        if file.enclosed_name().is_none() || contained(Path::new("/store"), &path).is_none() {
            fail(&format!("refusing unsafe export path: {path}"), None);
        }
        if let Some(mode) = file.unix_mode() {
            let kind = mode & 0o170000;
            if kind != 0 && kind != 0o100000 {
                fail(&format!("refusing non-file ZIP entry: {path}"), None);
            }
        }
        if !seen.insert(path.clone()) {
            fail(&format!("refusing duplicate export path: {path}"), None);
        }
        total = total.saturating_add(file.size());
        if total > MAX_STORE_BYTES {
            fail("store pack expands beyond the 512 MB limit", None);
        }
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .unwrap_or_else(|e| fail(&format!("could not decompress {path}: {e}"), None));
        if content.len() as u64 != file.size() {
            fail(&format!("store pack entry length mismatch: {path}"), None);
        }
        entries.push((path, content));
    }
    if entries.is_empty() {
        fail("hub returned an empty store pack", None);
    }
    entries
}

pub fn export(cfg: &Config, brain: &str, dir: Option<String>, skip_assets: bool) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/export?format=pack", enc(brain)),
            None,
            true,
        ),
        "export",
    );
    // The default dir name comes from the hub's slug — validate it before it
    // becomes a path (don't trust the hub response).
    let remote_slug = r.get("slug").and_then(|s| s.as_str()).filter(|s| {
        !s.is_empty()
            && s.len() <= 63
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !s.starts_with('-')
            && !s.ends_with('-')
    });
    let local_slug: String = brain
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let local_slug = local_slug.trim_matches('-');
    let dir = dir.unwrap_or_else(|| {
        format!(
            "./{}-export",
            remote_slug.unwrap_or(if local_slug.is_empty() {
                "brain"
            } else {
                local_slug
            })
        )
    });
    let root = std::fs::canonicalize(".")
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(&dir);
    let root = normalize(&root);

    let entries: Vec<(String, Vec<u8>)> = if let Some(url) = r.get("url").and_then(Value::as_str) {
        let expected = r
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| fail("hub returned an invalid pack hash", None));
        let pack = get_presigned(url, MAX_PACK_BYTES);
        let actual = format!("{:x}", Sha256::digest(&pack));
        if actual != expected {
            fail("downloaded store pack failed SHA-256 verification", None);
        }
        entries_from_pack(pack)
    } else {
        let files = r
            .get("files")
            .and_then(Value::as_array)
            .unwrap_or_else(|| fail("hub returned neither a store pack nor files", None));
        files
            .iter()
            .map(|file| {
                let path = file
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("refusing malformed file path from hub", None));
                let content = file
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("refusing malformed file content from hub", None));
                (path.to_string(), content.as_bytes().to_vec())
            })
            .collect()
    };

    // Gate the entire remote manifest before the first filesystem mutation.
    let mut seen = std::collections::HashSet::new();
    for (path, _) in &entries {
        if contained(&root, path).is_none() {
            fail(&format!("refusing unsafe export path: {path}"), None);
        }
        if !seen.insert(path) {
            fail(&format!("refusing duplicate export path: {path}"), None);
        }
    }
    std::fs::create_dir_all(&root)
        .unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", root.display()), None));
    let real_root = std::fs::canonicalize(&root)
        .unwrap_or_else(|e| fail(&format!("cannot resolve {}: {e}", root.display()), None));
    for (path, content) in &entries {
        let full = contained(&root, path)
            .unwrap_or_else(|| fail(&format!("refusing unsafe export path: {path}"), None));
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                fail(&format!("cannot create {}: {e}", parent.display()), None)
            });
            // The lexical containment above can be defeated by a symlinked
            // subdir INSIDE an existing target dir — re-check the REAL parent
            // after creation (exports into a fresh dir are unaffected).
            let real_parent = std::fs::canonicalize(parent).unwrap_or_else(|e| {
                fail(&format!("cannot resolve {}: {e}", parent.display()), None)
            });
            if !real_parent.starts_with(&real_root) {
                fail(
                    &format!(
                        "refusing export through a symlink escaping {}: {path}",
                        root.display()
                    ),
                    None,
                );
            }
        }
        // Never write THROUGH a pre-existing symlink at the leaf: a planted
        // link inside the target dir would redirect the write outside it
        // (the parent re-check above only covers directories).
        if let Ok(m) = std::fs::symlink_metadata(&full) {
            if m.file_type().is_symlink() {
                fail(
                    &format!("refusing to overwrite a symlink: {}", full.display()),
                    None,
                );
            }
        }
        std::fs::write(&full, content)
            .unwrap_or_else(|e| fail(&format!("write failed {}: {e}", full.display()), None));
    }
    let mut data = r.as_object().cloned().unwrap_or_default();
    data.remove("files");
    data.remove("url");
    data.insert("dir".into(), json!(dir));
    data.insert("fileCount".into(), json!(entries.len()));
    let mut human = format!("exported {} file(s) → {dir}", entries.len());

    // The byte half of the export: the store's manifest names every declared
    // blob — restore what is absent (or drifted) beside the markdown, each
    // download SHA-verified and containment-checked. The export is complete
    // files-on-disk either way; a failed asset names itself and the rest
    // continue.
    if !skip_assets {
        if let Some(restore) = crate::assets::restore_assets(cfg, brain, &root) {
            if restore.restored > 0 {
                human.push_str(&format!(
                    "\nassets: {} restored ({})",
                    restore.restored,
                    human_size(restore.restored_bytes)
                ));
            } else if restore.failed == 0 && restore.present > 0 {
                human.push_str(&format!("\nassets: all {} present", restore.present));
            }
            if restore.failed > 0 {
                human.push_str(&format!("\nassets: {} failed to restore", restore.failed));
            }
            data.insert("assetRestore".into(), restore.to_json());
        }
    }
    out(&human, Some(Value::Object(data)));
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// --- secrets (the vault) -------------------------------------------------------
//
// Write-only Cloudflare secret values bound to the brain's published functions
// (docs: /docs/publishing.md, "Functions + the vault"). The security contract,
// locked by tests: the VALUE is read from stdin only — never argv (argv is
// visible to every process on the machine), never echoed back on any path
// (prompts, errors, --json included). NAMES are public metadata (records
// declare them; the dashboard lists them) and are clap-validated to the hub's
// exact shape before any request.

/// clap value_parser for a secret NAME — the hub's gate, mirrored exactly:
/// `^[A-Z][A-Z0-9_]{0,63}$`. Refusal is a usage error (exit 2) before any I/O.
pub fn parse_secret_name(s: &str) -> Result<String, String> {
    let ok = matches!(s.as_bytes().first(), Some(b'A'..=b'Z'))
        && s.len() <= 64
        && s.bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
    if ok {
        Ok(s.to_string())
    } else {
        Err(
            "secret names are UPPER_SNAKE_CASE: start with A-Z, then A-Z/0-9/_, at most 64 chars (e.g. STRIPE_KEY)"
                .into(),
        )
    }
}

/// Trim exactly ONE trailing newline (`\n` or `\r\n`) — so `printf %s "$V" |`
/// and `echo "$V" |` both deliver the same value, while a value that really
/// ends in a newline can still be sent by appending one more.
fn trim_one_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Read the secret VALUE: prompted on the controlling terminal with echo OFF
/// when stdin is a TTY (rpassword talks to /dev/tty directly, so `--json`
/// stdout stays clean), else read whole from piped stdin. Never from argv;
/// never echoed — the refusal messages below name sizes and shapes, never
/// bytes.
fn secret_value_from_stdin(name: &str) -> String {
    use std::io::{IsTerminal, Read};
    let value = if std::io::stdin().is_terminal() {
        match rpassword::prompt_password(format!("value for {name} (input hidden): ")) {
            Ok(v) => v,
            Err(e) => fail(
                &format!(
                    "could not read from the terminal: {e} — pipe the value instead: printf %s \"$VALUE\" | sevra secrets set <brain> {name}"
                ),
                None,
            ),
        }
    } else {
        let stdin = std::io::stdin();
        let mut bytes = Vec::with_capacity(MAX_SECRET_STDIN_BYTES.min(8192));
        let mut limited = stdin.lock().take((MAX_SECRET_STDIN_BYTES + 1) as u64);
        if let Err(e) = limited.read_to_end(&mut bytes) {
            fail(
                &format!("could not read the value from stdin (it must be UTF-8): {e}"),
                None,
            );
        }
        if bytes.len() > MAX_SECRET_STDIN_BYTES {
            fail(
                &format!(
                    "the value is too large — the hub caps one secret at {MAX_SECRET_VALUE_CHARS} characters"
                ),
                None,
            );
        }
        let buf = match String::from_utf8(bytes) {
            Ok(buf) => buf,
            Err(_) => fail(
                "could not read the value from stdin (it must be UTF-8)",
                None,
            ),
        };
        trim_one_newline(buf)
    };
    if value.is_empty() {
        fail(
            &format!(
                "empty value — pipe the secret on stdin: printf %s \"$VALUE\" | sevra secrets set <brain> {name}"
            ),
            None,
        );
    }
    if value.chars().count() > MAX_SECRET_VALUE_CHARS {
        fail(
            &format!(
                "the value is {} characters — the hub caps one secret at {MAX_SECRET_VALUE_CHARS}",
                value.chars().count()
            ),
            None,
        );
    }
    value
}

pub fn secrets_list(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/secrets", enc(brain)),
            None,
            true,
        ),
        "secrets list",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let names: Vec<&str> = r
        .get("secrets")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if names.is_empty() {
        out(
            "no secrets provisioned — printf %s \"$VALUE\" | sevra secrets set <brain> NAME",
            None,
        );
    } else {
        out(
            &format!(
                "secrets ({}, values write-only): {}",
                names.len(),
                names.join(", ")
            ),
            None,
        );
    }
    let fns = r
        .get("functions")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    if fns.is_empty() {
        return;
    }
    out(&format!("functions ({}):", fns.len()), None);
    let join = |f: &Value, key: &str| -> String {
        let items: Vec<&str> = f
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if items.is_empty() {
            "-".into()
        } else {
            items.join(", ")
        }
    };
    for f in &fns {
        let live = if f.get("live").and_then(|l| l.as_bool()).unwrap_or(false) {
            "live"
        } else {
            "not live"
        };
        out(
            &format!(
                "  {}\t{}\tneeds: {}\tegress: {}",
                str_field(f, "name"),
                live,
                join(f, "secrets"),
                join(f, "egress")
            ),
            None,
        );
    }
}

pub fn secrets_set(cfg: &Config, brain: &str, name: &str, value_in_argv: bool) {
    if value_in_argv {
        // The trap arguments exist so this refusal happens WITHOUT echoing
        // what clap's own unexpected-argument error would have printed. The
        // argv exposure itself already happened at the OS level — say so.
        usage_fail(
            "the secret value is never taken from the command line (argv is visible to every process on the machine; it was NOT echoed here, but treat it as exposed). Pipe it on stdin instead: printf %s \"$VALUE\" | sevra secrets set <brain> NAME",
        );
    }
    // Before the prompt: never ask for a secret this process cannot send.
    if cfg.key.is_none() {
        fail(NOT_LOGGED_IN, None);
    }
    let value = secret_value_from_stdin(name);
    let body = json!({ "name": name, "value": value });
    let r = ensure_ok(
        request(
            cfg,
            "PUT",
            &format!("/api/hub/brains/{}/secrets", enc(brain)),
            Some(&body),
            true,
        ),
        "secrets set",
    );
    let hub_note = str_field(&r, "note");
    let human = if hub_note.is_empty() {
        format!("set secret {name} on {brain} (write-only)")
    } else {
        format!("set secret {name} on {brain} — {hub_note}")
    };
    out(&human, Some(r));
}

pub fn secrets_delete(cfg: &Config, brain: &str, name: &str) {
    let body = json!({ "name": name });
    let r = ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/secrets", enc(brain)),
            Some(&body),
            true,
        ),
        "secrets delete",
    );
    let mut data = r.as_object().cloned().unwrap_or_default();
    data.insert("name".into(), json!(name));
    out(
        &format!("deleted secret {name} from {brain} (unbound from its functions)"),
        Some(Value::Object(data)),
    );
}

// --- secrets scan / quarantine (the local store, no hub) -----------------------
//
// The other half of the vault story: secrets that are FILES in the store.
// `scan` is push's secret gate as a read-only report; `quarantine` gives the
// third exit — keep the files home in `.sevralocal` instead of shipping or
// editing them. Both are offline and need no credential. The one file sevra
// ever edits is `.sevralocal`, and only by appending.

/// The forward-only truth, stated on every quarantine run.
const FORWARD_ONLY_NOTE: &str = "kept-home is forward-only — files that already rode a push remain in earlier snapshots; marking removes them from the next snapshot and erases nothing";

/// `secrets scan [dir]` — the push secret scan, read-only: report what a
/// push of <dir> would refuse on, in exactly the push-refusal shape. Exit 1
/// on matches, 0 on a clean store; matched values are never shown. Honors
/// `.sevralocal`: kept-home files never ride, so they are not scanned here
/// (quarantine's full view is the one that sees them).
pub fn secrets_scan(dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| ".".into());
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    let (store, stats) = read_store_checked(&dir, true);
    if stats.kept_home > 0 {
        note(&format!(
            "{} file(s) kept home (.sevralocal) — not scanned; they never ride a push",
            stats.kept_home
        ));
    }
    let hits = scan_store(&store);
    if hits.is_empty() {
        out(
            &format!(
                "no matches for known secret formats across {} file(s)",
                stats.files
            ),
            Some(json!({ "secretHits": [], "total": 0 })),
        );
        return;
    }
    let mut msg = format!(
        "{} match(es) for known secret formats in the store (matched values are never shown):",
        hits.len()
    );
    msg.push_str(&secret_hits_block(&hits));
    msg.push_str(&format!(
        "\nrotate anything that ever lived here; keep live secrets in a password manager and references to them in the brain.\nkeep the files home instead of shipping them: `sevra secrets quarantine {dir}` — or edit them yourself"
    ));
    fail(&msg, Some(secret_hits_data(&hits)));
}

/// `secrets quarantine [dir]` — keep secret-bearing files home: scan the
/// FULL store (kept-home files included — that is what `alreadyCovered`
/// counts) and append each hit file's exact path to `.sevralocal`, creating
/// it when absent. Idempotent; `--dry-run` previews; `--closure` also marks
/// the files connected to a marked one through wiki-links (via `dbmd emit`).
/// `DB.md` and `assets.jsonl` are never marked — they ride every push, so a
/// secret inside them stays an edit case (warned, not acted on).
pub fn secrets_quarantine(dir: Option<String>, dry_run: bool, closure: bool) {
    let dir = dir.unwrap_or_else(|| ".".into());
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    // Load the scope directly (not through the walk): quarantine needs the
    // verbatim text to preserve, and a structurally invalid `.sevralocal`
    // refuses here exactly as push refuses.
    let scope = local::load(Path::new(&dir)).unwrap_or_else(|msg| fail(&msg, None));
    let covered = |p: &str| scope.as_ref().is_some_and(|s| s.keeps_home(p));
    let (store, _stats) = read_store_checked(&dir, false);
    let hits = scan_store(&store);

    // Unique hit files: exact path → shown (redacted) spelling.
    let mut hit_files: BTreeMap<String, String> = BTreeMap::new();
    for hit in &hits {
        hit_files
            .entry(hit.store_path.clone())
            .or_insert_with(|| hit.path.clone());
    }
    let mut warnings: Vec<(&'static str, String)> = Vec::new();
    // Warning: the filename itself is the secret. Reported per file, never
    // acted on — renaming is the operator's move (and the path is already
    // shown redacted by the scanner).
    let in_path_files: BTreeSet<&String> = hits
        .iter()
        .filter(|h| h.in_path)
        .map(|h| &h.store_path)
        .collect();
    for exact in &in_path_files {
        warnings.push(("filename_secret", hit_files[*exact].clone()));
    }

    let mut marked: Vec<(String, String)> = Vec::new(); // (exact, shown)
    let mut already_covered = 0usize;
    for (exact, shown) in &hit_files {
        if local::MUST_RIDE.contains(&exact.as_str()) {
            warnings.push(("must_ride", shown.clone()));
        } else if covered(exact) {
            already_covered += 1;
        } else {
            marked.push((exact.clone(), shown.clone()));
        }
    }

    // --closure: computed BEFORE any write — a missing dbmd fails up front.
    let closure_marked: Vec<String> = if closure {
        let emit = run_dbmd_emit(&dir);
        let seeds: BTreeSet<String> = marked.iter().map(|(exact, _)| exact.clone()).collect();
        closure_component(&emit, &seeds)
            .into_iter()
            .filter(|p| {
                !seeds.contains(p) && !covered(p) && !local::MUST_RIDE.contains(&p.as_str())
            })
            .collect() // BTreeSet iteration: already sorted
    } else {
        Vec::new()
    };

    // Warning: the asset manifest rides every push and still names kept-home
    // files (existing entries and this run's marks alike). Read-only over
    // the JSONL; malformed lines are tolerated silently.
    if let Some(assets) = store.assets.as_deref() {
        let mut named: BTreeSet<String> = BTreeSet::new();
        for line in assets.lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(p) = v.get("path").and_then(Value::as_str) else {
                continue;
            };
            let kept = covered(p)
                || marked.iter().any(|(exact, _)| exact == p)
                || closure_marked.iter().any(|exact| exact == p);
            if kept {
                named.insert(p.to_string());
            }
        }
        for p in named {
            warnings.push(("manifest_names_kept_home", redact_path(&p)));
        }
    }
    warnings.sort();

    // The write — the only file sevra ever edits, append-only. Exact paths
    // (escaped where a filename carries glob metacharacters), sorted.
    let mut new_entries: Vec<String> = marked
        .iter()
        .map(|(exact, _)| local::entry_for(exact))
        .chain(closure_marked.iter().map(|exact| local::entry_for(exact)))
        .collect();
    new_entries.sort();
    if !dry_run && !new_entries.is_empty() {
        let raw = scope.as_ref().map(|s| s.raw()).unwrap_or("");
        let body = local::append_entries(raw, &new_entries);
        std::fs::write(Path::new(&dir).join(local::FILE_NAME), body)
            .unwrap_or_else(|e| fail(&format!("could not write {}: {e}", local::FILE_NAME), None));
    }

    // Report. Shown spellings only (redacted wherever a path matched).
    let mut marked_shown: Vec<String> = marked.iter().map(|(_, shown)| shown.clone()).collect();
    marked_shown.sort();
    let closure_shown: Vec<String> = closure_marked.iter().map(|p| redact_path(p)).collect();
    let mut human = if hits.is_empty() {
        "no matches for known secret formats — nothing to keep home".to_string()
    } else if marked.is_empty() {
        "nothing new to mark".to_string()
    } else {
        let verb = if dry_run {
            "would keep home"
        } else {
            "kept home"
        };
        let mut s = format!("{verb} (.sevralocal): {} file(s)", marked_shown.len());
        for shown in &marked_shown {
            s.push_str(&format!("\n  {shown}"));
        }
        s
    };
    if !closure_shown.is_empty() {
        let verb = if dry_run { "would add" } else { "added" };
        human.push_str(&format!(
            "\nclosure {verb} {} linked file(s):",
            closure_shown.len()
        ));
        for shown in &closure_shown {
            human.push_str(&format!("\n  {shown}"));
        }
    }
    if already_covered > 0 {
        human.push_str(&format!(
            "\n{already_covered} hit file(s) already covered by .sevralocal"
        ));
    }
    for (kind, path) in &warnings {
        let line = match *kind {
            "filename_secret" => format!(
                "warning: {path} — the filename itself is the secret — consider renaming; a future feed removal would record the name"
            ),
            "must_ride" => format!(
                "warning: {path} carries a match but rides every push (store config / asset manifest) — never marked; edit it, the scanner keeps flagging it"
            ),
            _ => format!(
                "warning: assets.jsonl names {path} under a kept-home entry — the manifest rides and carries these names; removing entries is your deliberate edit"
            ),
        };
        human.push_str(&format!("\n{line}"));
    }
    if !json_mode() {
        note(FORWARD_ONLY_NOTE);
    }
    out(
        &human,
        Some(json!({
            "marked": marked_shown,
            "closureMarked": closure_shown,
            "alreadyCovered": already_covered,
            "warnings": warnings
                .iter()
                .map(|(kind, path)| json!({ "kind": kind, "path": path }))
                .collect::<Vec<_>>(),
            "total": hits.len(),
            "note": FORWARD_ONLY_NOTE,
        })),
    );
}

/// `--closure`'s graph source: `dbmd emit --json` run in the store. A
/// missing dbmd fails up front — before anything is written — with the
/// install hint; so does a failed or unparseable emit. Third-party error
/// text passes through the secret redactor before it is shown.
fn run_dbmd_emit(dir: &str) -> Value {
    let output = match Command::new("dbmd")
        .args(["emit", "--json"])
        .current_dir(dir)
        .output()
    {
        Ok(o) => o,
        Err(e) => fail(
            &format!(
                "--closure needs dbmd and it could not run (is it installed? https://www.sevrahq.com/install): {e}"
            ),
            None,
        ),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first: String = stderr
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        fail(
            &format!(
                "--closure: `dbmd emit` failed in {dir}: {}",
                redact_path(first.trim())
            ),
            None,
        );
    }
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        fail(
            &format!("--closure: `dbmd emit --json` produced unparseable output: {e}"),
            None,
        )
    })
}

/// The undirected reachability component of `seeds` over the content graph
/// `dbmd emit --json` describes (`files[].links`; targets arrive normalized
/// with `.md` appended). Nodes are the emitted files MINUS the root `DB.md`:
/// emit does include the store config, but it links broadly and must never
/// bridge otherwise-unconnected components (derived catalogs and the log are
/// already absent from emit, so over-marking through them cannot happen
/// either). An edge exists only between two emitted files — a dangling
/// target is nobody's bridge. Returns the component, seeds included.
fn closure_component(emit: &Value, seeds: &BTreeSet<String>) -> BTreeSet<String> {
    let files = emit
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let nodes: BTreeSet<&str> = files
        .iter()
        .filter_map(|f| f.get("path").and_then(Value::as_str))
        .filter(|p| *p != "DB.md")
        .collect();
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for f in &files {
        let Some(p) = f.get("path").and_then(Value::as_str) else {
            continue;
        };
        if p == "DB.md" {
            continue;
        }
        for link in f
            .get("links")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(t) = link.as_str() else { continue };
            if t != p && nodes.contains(t) {
                adj.entry(p).or_default().push(t);
                adj.entry(t).or_default().push(p);
            }
        }
    }
    let mut component: BTreeSet<String> = seeds.clone();
    let mut queue: VecDeque<&str> = nodes
        .iter()
        .copied()
        .filter(|n| seeds.contains(*n))
        .collect();
    while let Some(n) = queue.pop_front() {
        for next in adj.get(n).into_iter().flatten().copied() {
            if component.insert(next.to_string()) {
                queue.push_back(next);
            }
        }
    }
    component
}

// --- validate (shells dbmd) --------------------------------------------------

pub fn validate(dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| ".".into());
    // is_dir, not exists: handing dbmd a FILE as its working dir would fail
    // with a spawn error that misreads as "dbmd is not installed".
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    // The --json contract holds THROUGH the shell-out: dbmd has its own
    // global --json, so machine mode forwards it.
    let mut args = vec!["validate", "--all"];
    if json_mode() {
        args.push("--json");
    }
    match Command::new("dbmd").args(&args).current_dir(&dir).status() {
        Ok(status) => {
            // A signal death (no code) is not a pass.
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => fail(
            &format!("could not run dbmd (is it installed? https://www.sevrahq.com/install): {e}"),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contained_rejects_escapes() {
        let root = Path::new("/safe/root");
        assert!(contained(root, "notes/a.md").is_some());
        assert!(contained(root, "a.md").is_some());
        assert!(contained(root, "../a.md").is_none());
        assert!(contained(root, "notes/../../a.md").is_none());
        assert!(contained(root, "/etc/passwd").is_none());
        assert!(contained(root, "").is_none());
        assert!(contained(root, "a\0b").is_none());
        assert!(contained(root, "./a.md").is_none()); // hub paths are normalized; `./` is refused
    }

    #[test]
    fn normalize_pops_parents_lexically() {
        assert_eq!(
            normalize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
    }

    #[test]
    fn secret_name_shape_matches_the_hub_gate() {
        // ^[A-Z][A-Z0-9_]{0,63}$ — mirrored exactly, boundaries included.
        let max = "A".repeat(64);
        for good in ["A", "STRIPE_KEY", "A1_B2_C3", "OPENAI_API_KEY", &max] {
            assert!(parse_secret_name(good).is_ok(), "should accept {good}");
        }
        let over = "A".repeat(65);
        for bad in [
            "",
            "a",
            "lower_case",
            "1LEADING",
            "_LEADING",
            "HAS-DASH",
            "HAS SPACE",
            "Ä",
            "A\n",
            &over,
        ] {
            assert!(
                parse_secret_name(bad).is_err(),
                "should reject {}",
                bad.escape_debug()
            );
        }
    }

    #[test]
    fn human_size_speaks_the_hub_limit_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(256 * 1024 * 1024), "256.0 MiB");
        assert_eq!(human_size(512 * 1024 * 1024), "512.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn commas_group_thousands() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1000), "1,000");
        assert_eq!(commas(100_000), "100,000");
        assert_eq!(commas(1_234_567), "1,234,567");
    }

    #[test]
    fn query_target_resolves_positional_flag_and_conflicts() {
        let s = |v: &str| Some(v.to_string());
        // Positional form, unchanged.
        assert_eq!(
            resolve_query_target(None, s("b"), s("text")),
            Ok(("b".into(), Some("text".into())))
        );
        assert_eq!(
            resolve_query_target(None, s("b"), None),
            Ok(("b".into(), None))
        );
        // The flag alone, and the flag with text.
        assert_eq!(
            resolve_query_target(s("b"), None, None),
            Ok(("b".into(), None))
        );
        assert_eq!(
            resolve_query_target(s("b"), s("text"), None),
            Ok(("b".into(), Some("text".into())))
        );
        // Both forms: same brain proceeds, different brains refuse.
        assert_eq!(
            resolve_query_target(s("b"), s("b"), s("text")),
            Ok(("b".into(), Some("text".into())))
        );
        assert!(resolve_query_target(s("b"), s("other"), s("text"))
            .unwrap_err()
            .contains("--brain"));
        // No brain anywhere.
        assert!(resolve_query_target(None, None, None)
            .unwrap_err()
            .contains("which brain"));
    }

    fn emit_of(files: &[(&str, &[&str])]) -> Value {
        json!({
            "store": ".",
            "files": files
                .iter()
                .map(|(path, links)| json!({ "path": path, "links": links }))
                .collect::<Vec<_>>(),
            "summary": { "files": files.len() },
        })
    }

    fn seeds_of(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }

    fn sorted(set: BTreeSet<String>) -> Vec<String> {
        set.into_iter().collect()
    }

    #[test]
    fn closure_component_walks_links_undirected() {
        // a → b ← c: seeding a reaches c THROUGH b against the arrows.
        let emit = emit_of(&[
            ("a.md", &["b.md"]),
            ("b.md", &[]),
            ("c.md", &["b.md"]),
            ("d.md", &[]),
        ]);
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["a.md"]))),
            ["a.md", "b.md", "c.md"],
            "undirected through b; the isolated d stays out"
        );
    }

    #[test]
    fn closure_component_never_bridges_through_db_md_or_dangling_targets() {
        // DB.md links half the store — it must not connect components. Two
        // files sharing only a DANGLING target are not connected either.
        let emit = emit_of(&[
            ("DB.md", &["a.md", "d.md"]),
            ("a.md", &["DB.md"]),
            ("d.md", &[]),
            ("e.md", &["ghost.md"]),
            ("f.md", &["ghost.md"]),
        ]);
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["a.md"]))),
            ["a.md"],
            "DB.md is not a node, so it bridges nothing"
        );
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["e.md"]))),
            ["e.md"],
            "a dangling target is nobody's bridge"
        );
    }

    #[test]
    fn closure_component_keeps_unknown_seeds_and_survives_self_links() {
        let emit = emit_of(&[("g.md", &["g.md", "h.md"]), ("h.md", &[])]);
        // A seed emit never saw (e.g. a root-level hit file outside the
        // sources/records layers) rides through untouched.
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["outside.md"]))),
            ["outside.md"]
        );
        // A self-link is ignored; the real edge still walks.
        assert_eq!(
            sorted(closure_component(&emit, &seeds_of(&["g.md"]))),
            ["g.md", "h.md"]
        );
    }

    #[test]
    fn closure_component_tolerates_shapeless_emit_json() {
        assert_eq!(
            sorted(closure_component(&json!({}), &seeds_of(&["a.md"]))),
            ["a.md"],
            "no files array: the seeds are the component"
        );
    }

    #[test]
    fn trim_one_newline_trims_exactly_one() {
        assert_eq!(trim_one_newline("v\n".into()), "v");
        assert_eq!(trim_one_newline("v".into()), "v");
        assert_eq!(trim_one_newline("v\n\n".into()), "v\n"); // exactly one
        assert_eq!(trim_one_newline("v\r\n".into()), "v"); // CRLF is one newline
        assert_eq!(trim_one_newline("v\r".into()), "v\r"); // a bare CR is data
        assert_eq!(trim_one_newline("\n".into()), "");
        assert_eq!(trim_one_newline("multi\nline\n".into()), "multi\nline");
    }
}
