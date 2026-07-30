//! Offline behavior tests (assert_cmd) — the invariants that must hold with no
//! network: version shape, help, flag parsing, the not-logged-in path, the
//! HTTPS guard, and the --json error contract. The live hub parity proof is
//! the platform repo's hub-demo battery driven with SEVRA_BIN.

use assert_cmd::Command;
use predicates::prelude::*;

fn sevra() -> Command {
    let mut c = Command::cargo_bin("sevra").unwrap();
    // Isolate the home dir so no real ~/.sevra credential leaks in.
    // `home::home_dir()` reads HOME on unix and USERPROFILE on Windows —
    // set both so the isolation holds on every CI OS.
    let home = std::env::temp_dir().join(format!("sevra-test-{}", std::process::id()));
    c.env("HOME", &home);
    c.env("USERPROFILE", &home);
    c.env_remove("SEVRA_API_KEY");
    c.env_remove("SEVRA_HUB_URL");
    // No surprise release-check requests against test hubs.
    c.env("SEVRA_NO_AUTO_UPDATE", "1");
    c
}

#[test]
fn version_prints_semver() {
    sevra()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn version_json_is_machine_readable() {
    sevra()
        .args(["version", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"version\""));
}

#[test]
fn help_lists_commands() {
    sevra()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("login").and(predicate::str::contains("update")));
}

#[test]
fn unknown_command_errors() {
    sevra().arg("frobnicate").assert().failure();
}

#[test]
fn not_logged_in_is_clean() {
    sevra()
        .arg("brains")
        .env("SEVRA_HUB_URL", "https://www.sevrahq.com")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn refuses_non_https_hub() {
    sevra()
        .arg("whoami")
        .env("SEVRA_HUB_URL", "http://example.com")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing non-HTTPS hub"));
}

#[test]
fn ipv6_loopback_is_https_exempt() {
    // `http://[::1]:9` is loopback: it must pass the HTTPS guard and fail
    // only on reachability (nothing listens on port 9).
    sevra()
        .arg("whoami")
        .env("SEVRA_HUB_URL", "http://[::1]:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing non-HTTPS hub").not())
        .stderr(predicate::str::contains("hub unreachable"));
}

#[test]
fn empty_env_key_reads_as_unset() {
    // SEVRA_API_KEY="" must fall through to "not logged in", not send an empty
    // bearer (the TS `||` truthiness parity).
    sevra()
        .arg("brains")
        .env("SEVRA_HUB_URL", "https://www.sevrahq.com")
        .env("SEVRA_API_KEY", "")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn json_error_contract_on_stdout() {
    // In --json mode, a failure emits a JSON object on stdout (never a bare
    // stderr line), so a parsing agent still gets structured output.
    sevra()
        .args(["whoami", "--json"])
        .env("SEVRA_HUB_URL", "http://example.com")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"error\""));
}

#[test]
fn validate_reports_missing_dir() {
    sevra()
        .args(["validate", "./definitely-not-a-dir-xyz"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("directory not found"));
}

#[test]
fn json_flag_before_positional_is_not_swallowed() {
    // `query --json <brain> <text>` — clap keeps --json a boolean; the brain +
    // text stay positional. It fails on the unreachable hub, but in JSON mode.
    sevra()
        .args(["query", "--json", "somebrain", "scope creep"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"error\""));
}

#[test]
fn malformed_key_never_leaks_into_output() {
    // A key with an INTERIOR control byte cannot travel in a header; ureq's
    // own validation error would echo the ENTIRE authorization header. The
    // CLI must refuse it first — and the secret must appear nowhere in
    // stdout or stderr, in either output mode. (Trailing whitespace is the
    // separate, trimmed-and-proceed case below.)
    for json in [false, true] {
        let mut c = sevra();
        c.arg("brains");
        if json {
            c.arg("--json");
        }
        let out = c
            .env("SEVRA_HUB_URL", "http://localhost:9")
            .env("SEVRA_API_KEY", "sevra_account_TOPSECRET\nLEAKCHECK")
            .output()
            .unwrap();
        assert!(!out.status.success());
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!all.contains("TOPSECRET"), "key leaked into output: {all}");
        assert!(all.contains("re-copy it from the dashboard"), "got: {all}");
    }
}

#[test]
fn key_with_surrounding_whitespace_is_trimmed_not_refused() {
    // Trim the paste artifact and proceed — the request then fails on auth
    // (or reachability), never on the header.
    sevra()
        .arg("brains")
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", " sevra_account_x \n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("hub unreachable"));
}

#[test]
fn version_flag_honors_json() {
    // clap's built-in --version must not break the JSON contract.
    sevra()
        .args(["--json", "--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"version\""));
    sevra()
        .args(["--json", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"help\""));
}

#[test]
fn logout_without_credential_is_honest() {
    sevra()
        .arg("logout")
        .assert()
        .success()
        .stdout(predicate::str::contains("no stored credential"));
}

#[test]
fn inbox_action_and_graph_dir_are_usage_checked() {
    // Bad enum values are clap usage errors (exit 2), honoring --json.
    sevra()
        .args(["inbox", "purge", "b", "--json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"error\""));
    sevra()
        .args(["graph", "b", "p", "--dir", "sideways"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("possible values"));
}

#[test]
fn validate_rejects_a_regular_file() {
    // A FILE as the store dir must not misreport as "dbmd not installed".
    let tmp = std::env::temp_dir().join(format!("sevra-vf-{}", std::process::id()));
    std::fs::write(&tmp, "not a dir").unwrap();
    sevra()
        .arg("validate")
        .arg(&tmp)
        .assert()
        .failure()
        .stderr(predicate::str::contains("directory not found"));
    let _ = std::fs::remove_file(&tmp);
}

// --- secrets (the vault): the no-leak contract ---------------------------------

/// stdout + stderr of one run, as one searchable string.
fn all_output(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn secrets_help_lists_actions_and_hides_the_argv_trap() {
    sevra()
        .args(["secrets", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("list")
                .and(predicate::str::contains("set"))
                .and(predicate::str::contains("delete")),
        );
    // The hidden traps must not advertise a value positional in usage.
    sevra()
        .args(["secrets", "set", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("[REFUSED]")
                .not()
                .and(predicate::str::contains("--value").not()),
        );
}

#[test]
fn secrets_name_is_clap_validated() {
    // Bad names are usage errors (exit 2) before any I/O — the hub's
    // ^[A-Z][A-Z0-9_]{0,63}$ mirrored client-side. Names are public metadata,
    // so clap echoing them is fine.
    let over = "A".repeat(65);
    for bad in ["lower", "1LEADING", "_LEAD", "HAS-DASH", over.as_str()] {
        sevra()
            .args(["secrets", "set", "b", bad])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("UPPER_SNAKE_CASE"));
    }
    // delete validates too, and the usage error honors --json on stdout.
    sevra()
        .args(["secrets", "delete", "b", "bad-name", "--json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"error\""));
}

#[test]
fn secrets_value_in_argv_is_refused_and_never_echoed() {
    // The classic mistake: `sevra secrets set b NAME "$VALUE"` (or --value).
    // It must be refused as a usage error (exit 2) and the would-be secret
    // must appear NOWHERE in the output — clap's own unexpected-argument
    // error would have echoed it; the hidden traps exist to prevent that.
    let cases: &[&[&str]] = &[
        &["secrets", "set", "b", "API_KEY", "hunter2-argv-secret"],
        &[
            "secrets",
            "set",
            "b",
            "API_KEY",
            "hunter2-argv-secret",
            "part2",
        ],
        &[
            "secrets",
            "set",
            "b",
            "API_KEY",
            "--value=hunter2-argv-secret",
        ],
        &[
            "secrets",
            "set",
            "b",
            "API_KEY",
            "--value",
            "hunter2-argv-secret",
        ],
    ];
    for json in [false, true] {
        for case in cases {
            let mut c = sevra();
            c.args(*case);
            if json {
                c.arg("--json");
            }
            let out = c.output().unwrap();
            assert_eq!(out.status.code(), Some(2), "case {case:?}");
            let all = all_output(&out);
            assert!(
                !all.contains("hunter2"),
                "secret echoed for {case:?}: {all}"
            );
            assert!(all.contains("stdin"), "should point at stdin: {all}");
            if json {
                assert!(
                    String::from_utf8_lossy(&out.stdout).contains("\"error\""),
                    "--json contract broken: {all}"
                );
            }
        }
    }
}

#[test]
fn secrets_set_value_never_leaks_on_failure_paths() {
    // The value crosses the whole pipeline (stdin read → validation → request)
    // and the request then fails. On EVERY path, in BOTH output modes, the
    // value appears nowhere in stdout/stderr.
    for json in [false, true] {
        // Logged in (env key), unreachable hub → transport failure AFTER the
        // value was read and placed in the request body.
        let mut c = sevra();
        c.args(["secrets", "set", "b", "API_KEY"]);
        if json {
            c.arg("--json");
        }
        let out = c
            .env("SEVRA_HUB_URL", "http://localhost:9")
            .env("SEVRA_API_KEY", "x")
            .write_stdin("vault-TOPSECRET-value\n")
            .output()
            .unwrap();
        assert!(!out.status.success());
        let all = all_output(&out);
        assert!(!all.contains("TOPSECRET"), "value leaked: {all}");
        assert!(all.contains("hub unreachable"), "got: {all}");

        // Not logged in → refused BEFORE the value is even read (never prompt
        // for a secret the process cannot send) — and still no leak.
        let mut c = sevra();
        c.args(["secrets", "set", "b", "API_KEY"]);
        if json {
            c.arg("--json");
        }
        let out = c
            .env("SEVRA_HUB_URL", "https://www.sevrahq.com")
            .write_stdin("vault-TOPSECRET-value\n")
            .output()
            .unwrap();
        assert!(!out.status.success());
        let all = all_output(&out);
        assert!(!all.contains("TOPSECRET"), "value leaked: {all}");
        assert!(all.contains("not logged in"), "got: {all}");
    }
}

#[test]
fn secrets_set_refuses_empty_and_oversized_values_without_echo() {
    // "\n" is one trimmed newline → empty → refused with an instruction (the
    // ordering proof: a piped value present + no login fails "not logged in",
    // so this failing "empty value" proves the read happens after auth).
    sevra()
        .args(["secrets", "set", "b", "API_KEY"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty value"));
    // >4096 chars is refused client-side, naming the size, never the bytes.
    let big = "x".repeat(4097);
    let out = sevra()
        .args(["secrets", "set", "b", "API_KEY"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .write_stdin(big.clone())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = all_output(&out);
    assert!(all.contains("4096"), "should name the cap: {all}");
    assert!(all.contains("4097"), "should name the actual size: {all}");
    assert!(
        !all.contains("xxxxxxxx"),
        "value bytes echoed into output: {all}"
    );

    // The byte-level ceiling fires before UTF-8 decoding/character counting,
    // bounding memory even when a hostile producer never sends a newline.
    let byte_flood = "x".repeat(4096 * 4 + 3);
    let out = sevra()
        .args(["secrets", "set", "b", "API_KEY"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .write_stdin(byte_flood)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = all_output(&out);
    assert!(all.contains("too large"), "should name the boundary: {all}");
    assert!(
        !all.contains("xxxxxxxx"),
        "value bytes echoed into output: {all}"
    );
}

#[test]
fn secrets_list_and_delete_hold_the_json_error_contract() {
    // Wiring smoke: both route through the hub client, honoring --json.
    sevra()
        .args(["secrets", "list", "b", "--json"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"error\""));
    sevra()
        .args(["secrets", "delete", "b", "API_KEY"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("hub unreachable"));
}

// --- device-flow sign-in (`sevra login` with no key), on a mock loopback hub -
// Loopback HTTP is exempt from the HTTPS guard, so a hand-rolled TcpListener
// plays the hub: start → poll(pending) → poll(approved with a key) → the /me
// probe. Zero new dev-deps, same idiom as dbmd's mock hubs.

use std::io::{BufRead, BufReader, Read as IoRead, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct MockReq {
    method: String,
    path: String,
    authorization: Option<String>,
    body: String,
}

fn read_mock_request(stream: &mut TcpStream) -> Option<MockReq> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut content_length = 0usize;
    let mut authorization = None;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let t = h.trim();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if k.eq_ignore_ascii_case("authorization") {
                authorization = Some(v.trim().to_string());
            }
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some(MockReq {
        method,
        path,
        authorization,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn respond_json(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let msg = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(msg.as_bytes());
}

/// Serve `responses` in order, one connection each, recording every request.
/// `{BASE}` inside a body is replaced with the hub's own base URL.
fn mock_hub(
    responses: Vec<(u16, String)>,
) -> (
    String,
    Arc<Mutex<Vec<MockReq>>>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // Bounded accept: if the client makes FEWER requests than there are queued
    // responses, the thread must not block on accept() forever (that hangs
    // handle.join() and, with the shared build lock, the whole suite). Poll
    // non-blocking against a deadline instead, then return — the test's
    // request-count assertions surface the mismatch loudly rather than hanging.
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let log: Arc<Mutex<Vec<MockReq>>> = Arc::new(Mutex::new(Vec::new()));
    let (log2, base2) = (log.clone(), base.clone());
    let handle = std::thread::spawn(move || {
        for (status, body) in responses {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return; // no connection arrived — give up, don't hang
                        }
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => return,
                }
            };
            stream.set_nonblocking(false).unwrap();
            let Some(req) = read_mock_request(&mut stream) else {
                continue;
            };
            log2.lock().unwrap().push(req);
            // status 0 = a transport failure: log the request, then drop the
            // connection without answering (the client sees a reset).
            if status == 0 {
                continue;
            }
            respond_json(&mut stream, status, &body.replace("{BASE}", &base2));
        }
    });
    (base, log, handle)
}

fn sevra_at_home(home: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("sevra").unwrap();
    c.env("HOME", home);
    c.env("USERPROFILE", home);
    c.env_remove("SEVRA_API_KEY");
    c.env_remove("SEVRA_HUB_URL");
    c.env("SEVRA_NO_AUTO_UPDATE", "1");
    c
}

const MOCK_KEY: &str =
    "sevra_account_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn device_start_body() -> String {
    concat!(
        r#"{"deviceCode":"dev-code-abcdefghijklmnopqrstuv","userCode":"BCDF-GHJK","#,
        r#""verificationUri":"{BASE}/device","#,
        r#""verificationUriComplete":"{BASE}/device?code=BCDF-GHJK","#,
        r#""expiresIn":60,"interval":0}"#
    )
    .to_string()
}

#[test]
fn device_flow_signs_in_end_to_end() {
    let home = tempfile::tempdir().unwrap();
    let approved = format!(
        r#"{{"status":"approved","key":"{MOCK_KEY}","keyId":"01x","hint":"cdef","email":"t@example.com"}}"#
    );
    // No /me probe on the device path: redemption already proves the binding
    // and returns the email, so start + two polls is the whole conversation.
    let (base, log, handle) = mock_hub(vec![
        (201, device_start_body()),
        (200, r#"{"status":"pending"}"#.to_string()),
        (200, approved),
    ]);

    let out = sevra_at_home(home.path())
        .args(["login", "--hub", &base, "--no-browser"])
        .output()
        .unwrap();
    assert!(out.status.success(), "login failed: {}", all_output(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("BCDF-GHJK"), "code shown: {stdout}");
    assert!(
        stdout.contains("/device?code=BCDF-GHJK"),
        "complete URL shown: {stdout}"
    );
    assert!(
        stdout.contains("logged in to") && stdout.contains("t@example.com"),
        "final line names the account without a probe: {stdout}"
    );

    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 3, "start + two polls, no /me probe: {reqs:?}");
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/hub/auth/device");
    assert!(reqs[1].path.ends_with("/device/token"));
    assert!(
        reqs[1].body.contains("dev-code-abcdefghijklmnopqrstuv"),
        "poll carries the device code: {:?}",
        reqs[1]
    );
    assert!(
        reqs.iter().all(|r| r.path != "/api/hub/me"),
        "device path must not probe /me: {reqs:?}"
    );

    let config = std::fs::read_to_string(home.path().join(".sevra/config.json")).unwrap();
    assert!(config.contains(MOCK_KEY), "key persisted");
    assert!(config.contains(&base), "hub persisted");
    assert!(
        config.contains("01x"),
        "device key_id persisted for logout revoke"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(home.path().join(".sevra/config.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "credential file must be 0600");
    }
}

#[test]
fn browser_flow_falls_back_to_the_code_flow_when_no_browser_opens() {
    // The automatic path needs a browser. In this environment we force the
    // code flow with --no-browser and assert the fallback path still signs in
    // end to end (start + poll + approved), never touching the loopback
    // endpoints. This is the SSH / headless contract.
    let home = tempfile::tempdir().unwrap();
    let approved = format!(
        r#"{{"status":"approved","key":"{MOCK_KEY}","keyId":"01x","hint":"cdef","email":"t@example.com"}}"#
    );
    let (base, log, handle) = mock_hub(vec![(201, device_start_body()), (200, approved)]);
    let out = sevra_at_home(home.path())
        .args(["login", "--hub", &base, "--no-browser"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "code-flow login: {}",
        all_output(&out)
    );
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(
        reqs[0].path, "/api/hub/auth/device",
        "went straight to the code flow"
    );
    assert!(
        reqs.iter()
            .all(|r| !r.path.starts_with("/api/hub/auth/cli")),
        "--no-browser must not touch the loopback endpoints: {reqs:?}"
    );
    let config = std::fs::read_to_string(home.path().join(".sevra/config.json")).unwrap();
    assert!(config.contains(MOCK_KEY), "session persisted");
}

#[test]
fn device_flow_recovers_from_a_transport_blip_mid_poll() {
    // The bug this guards: a poll that hit a transport error used to abort the
    // whole login. Now a dropped connection (status 0) is retried, and the
    // still-valid approval is collected on the next poll.
    let home = tempfile::tempdir().unwrap();
    let approved = format!(
        r#"{{"status":"approved","key":"{MOCK_KEY}","keyId":"01x","hint":"cdef","email":"t@example.com"}}"#
    );
    let (base, log, handle) = mock_hub(vec![
        (201, device_start_body()),
        (0, String::new()), // wifi blip: connection dropped mid-poll
        (200, approved),
    ]);
    let out = sevra_at_home(home.path())
        .args(["login", "--hub", &base, "--no-browser"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a transport blip must not kill the login: {}",
        all_output(&out)
    );
    handle.join().unwrap();
    assert_eq!(
        log.lock().unwrap().len(),
        3,
        "start, dropped poll, retry poll"
    );
    let config = std::fs::read_to_string(home.path().join(".sevra/config.json")).unwrap();
    assert!(config.contains(MOCK_KEY), "key persisted after recovery");
}

#[test]
fn logout_revokes_a_device_minted_key_server_side() {
    // A device login mints a fresh key; logout must revoke it server-side (via
    // the bearer) so keys don't pile up against the cap — while still removing
    // the local config.
    let home = tempfile::tempdir().unwrap();
    let approved = format!(
        r#"{{"status":"approved","key":"{MOCK_KEY}","keyId":"01x","hint":"cdef","email":"t@example.com"}}"#
    );
    let (base, log, handle) = mock_hub(vec![
        (201, device_start_body()),
        (200, approved),
        (200, r#"{"revoked":true}"#.to_string()), // the logout revoke
    ]);

    let login = sevra_at_home(home.path())
        .args(["login", "--hub", &base, "--no-browser"])
        .output()
        .unwrap();
    assert!(login.status.success(), "login: {}", all_output(&login));

    let logout = sevra_at_home(home.path()).arg("logout").output().unwrap();
    assert!(logout.status.success(), "logout: {}", all_output(&logout));

    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    let revoke = reqs.last().expect("a revoke request");
    assert_eq!(revoke.path, "/api/hub/keys/revoke-self");
    assert_eq!(
        revoke.authorization.as_deref(),
        Some(format!("Bearer {MOCK_KEY}").as_str()),
        "revoke presents the very key being revoked"
    );
    assert!(
        !home.path().join(".sevra/config.json").exists(),
        "local config removed on logout"
    );
}

#[test]
fn device_flow_denied_is_a_clean_failure() {
    let home = tempfile::tempdir().unwrap();
    let (base, _log, handle) = mock_hub(vec![
        (201, device_start_body()),
        (200, r#"{"status":"denied"}"#.to_string()),
    ]);
    let out = sevra_at_home(home.path())
        .args(["login", "--hub", &base, "--no-browser"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("denied"), "names the denial: {stderr}");
    assert!(
        !home.path().join(".sevra/config.json").exists(),
        "no credential written on denial"
    );
    handle.join().unwrap();
}

#[test]
fn device_flow_expired_code_says_run_again() {
    let home = tempfile::tempdir().unwrap();
    let (base, _log, handle) = mock_hub(vec![
        (201, device_start_body()),
        (
            400,
            r#"{"error":"The code expired. Run `sevra login` again.","code":"expired"}"#
                .to_string(),
        ),
    ]);
    let out = sevra_at_home(home.path())
        .args(["login", "--hub", &base, "--no-browser"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("expired"), "names the expiry: {stderr}");
    handle.join().unwrap();
}

#[test]
fn device_flow_json_emits_awaiting_line_then_result() {
    let home = tempfile::tempdir().unwrap();
    let approved = format!(
        r#"{{"status":"approved","key":"{MOCK_KEY}","keyId":"01x","hint":"cdef","email":"t@example.com"}}"#
    );
    // No /me response: the device path does not probe. start + one poll only.
    let (base, _log, handle) = mock_hub(vec![(201, device_start_body()), (200, approved)]);
    let out = sevra_at_home(home.path())
        .args(["login", "--hub", &base, "--json", "--no-browser"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.contains("\"awaiting_approval\"")
            && first_line.contains("/device?code=BCDF-GHJK"),
        "first stdout line is the compact awaiting event: {first_line}"
    );
    assert!(
        stdout.contains("\"email\": \"t@example.com\""),
        "final object carries the account: {stdout}"
    );
    handle.join().unwrap();
}

#[test]
fn device_flow_unreachable_hub_fails_fast() {
    let home = tempfile::tempdir().unwrap();
    sevra_at_home(home.path())
        .args(["login", "--hub", "http://127.0.0.1:9", "--no-browser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("hub unreachable"));
}

// --- mcp: the stdio MCP server over the read surface ---------------------------
// The protocol core's battery lives in src/mcp.rs; these prove the stdio shell
// end to end — stdout carries ONLY JSON-RPC frames, and the hub client sends
// (or omits) the bearer exactly as the resolved credential dictates.

#[test]
fn mcp_speaks_json_rpc_on_stdout_only() {
    // initialize + notification + tools/list + garbage: exactly three response
    // lines (the notification is silent), no network touched. A stray --json
    // must not corrupt the protocol stream either.
    let out = sevra()
        .args(["mcp", "--json"])
        .write_stdin(concat!(
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            "\n",
            "not json\n",
        ))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "init + list + parse error; the notification stays silent: {stdout}"
    );
    assert!(
        lines[0].contains(r#""protocolVersion":"2025-03-26""#) && lines[0].contains("sevra-brain"),
        "initialize echoes the known protocol: {}",
        lines[0]
    );
    assert!(
        lines[1].contains(r#""name":"list_brains""#) && lines[1].contains(r#""name":"graph""#),
        "tools/list names the surface: {}",
        lines[1]
    );
    assert!(lines[2].contains("-32700"), "parse error: {}", lines[2]);
    // Diagnostics live on stderr: the ready line, and the no-credential warning.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ready"), "stderr: {stderr}");
    assert!(stderr.contains("public brains"), "stderr: {stderr}");
}

#[test]
fn mcp_tools_call_reaches_the_hub_with_the_stored_bearer() {
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"brains":[{"id":"01brain","slug":"work","name":"Work","scope":"personal"}]}"#
            .to_string(),
    )]);
    let out = sevra()
        .arg("mcp")
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "sevra_account_mcp")
        .write_stdin(concat!(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_brains","arguments":{}}}"#,
            "\n"
        ))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/api/hub/brains");
    assert_eq!(
        reqs[0].authorization.as_deref(),
        Some("Bearer sevra_account_mcp"),
        "the resolved credential rides the read call"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#""isError":false"#), "{stdout}");
    assert!(
        stdout.contains("01brain"),
        "the tool text carries the hub body: {stdout}"
    );
}

// --- push preflights, --force, delete, query --brain (the 0.2.4 surface) -----

/// A minimal valid store on disk; returns the tempdir guard.
fn store_dir(files: &[(&str, &str)]) -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    for (name, content) in files {
        let path = t.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    t
}

#[test]
fn push_help_states_replacement_and_the_new_flags() {
    sevra().args(["push", "--help"]).assert().success().stdout(
        predicate::str::contains("REPLACES")
            .and(predicate::str::contains("removed from"))
            .and(predicate::str::contains("--force"))
            .and(predicate::str::contains("--allow-secrets"))
            .and(predicate::str::contains(".sevralocal"))
            .and(predicate::str::contains("never part of the cargo")),
    );
}

#[test]
fn query_accepts_brain_as_a_flag() {
    // The dogfood bug: `sevra query --brain X "text"` was an "unexpected
    // argument" usage error while push spelled the brain exactly that way.
    let (base, log, handle) = mock_hub(vec![
        (200, r#"{"total":0,"results":[]}"#.to_string()),
        (200, r#"{"total":0,"results":[]}"#.to_string()),
    ]);
    sevra()
        .args(["query", "--brain", "workbrain", "scope creep"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success();
    // Belt and braces: both forms naming the SAME brain proceed.
    sevra()
        .args(["query", "workbrain", "scope creep", "--brain", "workbrain"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success();
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    for req in reqs.iter() {
        assert_eq!(req.path, "/api/hub/brains/workbrain/query?q=scope%20creep");
    }
}

#[test]
fn query_with_two_differing_brains_is_a_usage_error() {
    sevra()
        .args(["query", "one", "text", "--brain", "two"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--brain").and(predicate::str::contains("pass it once")));
    // The --json contract holds for the refusal.
    sevra()
        .args(["query", "one", "text", "--brain", "two", "--json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"error\""));
}

#[test]
fn push_force_sends_allow_shrink_and_plain_push_does_not() {
    let t = store_dir(&[("a.md", "alpha")]);
    let (base, log, handle) = mock_hub(vec![
        (200, r#"{"indexed":{"documents":1}}"#.to_string()),
        (200, r#"{"indexed":{"documents":1}}"#.to_string()),
    ]);
    sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success();
    sevra()
        .args([
            "push",
            t.path().to_str().unwrap(),
            "--brain",
            "b",
            "--force",
        ])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success();
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].path, "/api/hub/brains/b/push");
    assert!(
        !reqs[0].body.contains("allow_shrink"),
        "no allow_shrink without --force: {}",
        reqs[0].body
    );
    assert!(
        reqs[1].body.contains(r#""allow_shrink":true"#),
        "--force rides as allow_shrink: {}",
        reqs[1].body
    );
}

#[test]
fn push_shrink_refusal_shows_the_hub_message_and_the_force_hint() {
    let t = store_dir(&[("a.md", "alpha")]);
    let (base, _log, handle) = mock_hub(vec![(
        409,
        r#"{"error":"replacing 120 documents with 1 shrinks this brain","code":"shrink_refused","currentDocs":120,"incomingDocs":1}"#
            .to_string(),
    )]);
    sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("replacing 120 documents with 1 shrinks this brain")
                .and(predicate::str::contains("retry with --force")),
        );
    handle.join().unwrap();
}

#[test]
fn push_refuses_secrets_before_any_request_and_never_echoes_them() {
    // Fixture token built at runtime so no secret-shaped literal sits in the
    // repo. The hub URL is unreachable: the refusal proves the scan runs
    // before any network I/O.
    let key = format!("AKIA{}", "A".repeat(16));
    let t = store_dir(&[("note.md", &format!("aws key: {key}"))]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = all_output(&out);
    assert!(all.contains("AWS access key id"), "names the kind: {all}");
    assert!(all.contains("note.md"), "names the file: {all}");
    assert!(all.contains("rotate"), "remediation line: {all}");
    assert!(
        !all.contains(&key),
        "the matched value must never print: {all}"
    );
    assert!(
        !all.contains("hub unreachable"),
        "the scan must refuse before any request: {all}"
    );
    // The three exits, in order: keep home · edit · override.
    let quarantine = all.find("secrets quarantine").expect("names quarantine");
    let edit = all.find("edit the files").expect("names the edit path");
    let allow = all.find("--allow-secrets").expect("names the override");
    assert!(
        quarantine < edit && edit < allow,
        "exits out of order: {all}"
    );
}

#[cfg(unix)]
#[test]
fn push_refuses_an_external_symlink_before_any_request_or_read() {
    let store = store_dir(&[("DB.md", "# safe")]);
    let outside = tempfile::tempdir().unwrap();
    let secret = "EXTERNAL-CONTENT-MUST-NOT-RIDE";
    std::fs::write(outside.path().join("private.md"), secret).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("private.md"),
        store.path().join("shared.md"),
    )
    .unwrap();

    let out = sevra()
        .args(["push", store.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = all_output(&out);
    assert!(all.contains("shared.md"), "names the hostile link: {all}");
    assert!(
        all.contains("resolves outside the store"),
        "explains the boundary: {all}"
    );
    assert!(
        !all.contains(secret),
        "external bytes leaked into output: {all}"
    );
    assert!(
        !all.contains("hub unreachable"),
        "the filesystem refusal must happen before the request: {all}"
    );
}

#[test]
fn push_allow_secrets_overrides_the_scan() {
    let key = format!("AKIA{}", "B".repeat(16));
    let t = store_dir(&[("note.md", &format!("aws key: {key}"))]);
    // Same store, with the override: the push proceeds to the (unreachable)
    // hub — the failure is now transport, not the scan.
    sevra()
        .args([
            "push",
            t.path().to_str().unwrap(),
            "--brain",
            "b",
            "--allow-secrets",
        ])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("hub unreachable"));
}

#[test]
fn push_flags_a_secret_in_a_file_name_without_reprinting_it() {
    let token = format!("ghp_{}", "a".repeat(36));
    let t = store_dir(&[(&format!("{token}.md"), "clean content")]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = all_output(&out);
    assert!(
        all.contains("GitHub personal access token"),
        "names the kind: {all}"
    );
    assert!(all.contains("file's name"), "says WHERE it sits: {all}");
    assert!(
        !all.contains(&token),
        "a secret-bearing path must print redacted: {all}"
    );
}

#[test]
fn delete_without_confirm_needs_a_terminal() {
    // Piped stdin is not a TTY: the refusal must name --confirm and happen
    // before any network I/O (the hub here is unreachable).
    sevra()
        .args(["delete", "workbrain"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("--confirm")
                .and(predicate::str::contains("hub unreachable").not()),
        );
}

#[test]
fn delete_with_confirm_sends_the_slug_and_reports_the_removal() {
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"deleted":true,"brain":"01brain","r2Objects":7}"#.to_string(),
    )]);
    sevra()
        .args(["delete", "workbrain", "--confirm", "workbrain"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success()
        .stdout(predicate::str::contains("deleted").and(predicate::str::contains("7")));
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "DELETE");
    assert_eq!(reqs[0].path, "/api/hub/brains/workbrain");
    assert!(
        reqs[0].body.contains(r#""confirm":"workbrain""#),
        "the slug rides the body: {}",
        reqs[0].body
    );
}

#[test]
fn delete_maps_the_hubs_confirm_required_refusal() {
    let (base, _log, handle) = mock_hub(vec![(
        400,
        r#"{"error":"Confirm by sending the brain's slug.","code":"confirm_required"}"#.to_string(),
    )]);
    sevra()
        .args(["delete", "workbrain", "--confirm", "wrong-slug"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Confirm by sending the brain's slug.")
                .and(predicate::str::contains("--confirm")),
        );
    handle.join().unwrap();
}

#[test]
fn non_json_error_bodies_surface_their_start() {
    // A proxy answering HTML used to read as a bare "unknown error"; the
    // start of the actual body now rides along.
    let (base, _log, handle) = mock_hub(vec![(
        502,
        "<html>Bad gateway from an intermediate proxy</html>".to_string(),
    )]);
    sevra()
        .arg("brains")
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("unknown error").and(predicate::str::contains(
                "Bad gateway from an intermediate proxy",
            )),
        );
    handle.join().unwrap();
}

// --- .sevralocal + secrets scan/quarantine (the 0.2.5 surface) ----------------
// Secrets get a place that is not the hub: a kept-home list the push walk
// honors, a read-only scan, and a quarantine that appends hit files to the
// list. Everything here is offline except the push wiring against mock hubs.

#[test]
fn push_keeps_sevralocal_files_home_and_reports_it() {
    let t = store_dir(&[
        ("a.md", "rides"),
        ("private.md", "stays-home"),
        (".sevralocal", "private.md\n"),
    ]);
    let (base, log, handle) = mock_hub(vec![
        (200, r#"{"indexed":{"documents":1}}"#.to_string()),
        (200, r#"{"indexed":{"documents":1}}"#.to_string()),
    ]);
    sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("pushed 1 files").and(predicate::str::contains(
                "1 file(s) kept home (.sevralocal)",
            )),
        );
    // --json carries the same fact for machines.
    sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b", "--json"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"keptHome\": 1"));
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    for req in reqs.iter() {
        assert!(req.body.contains("a.md"), "the riding file: {}", req.body);
        assert!(
            !req.body.contains("private.md") && !req.body.contains("stays-home"),
            "a kept-home file must never leave the machine: {}",
            req.body
        );
        assert!(
            !req.body.contains("sevralocal"),
            "the list itself never uploads: {}",
            req.body
        );
    }
}

#[test]
fn push_with_an_active_sevralocal_keeps_derived_catalogs_home() {
    // Active by entry (even one matching nothing): catalogs carry every
    // file's name/title/summary — kept-home files included — so they stay
    // home too; the hub rebuilds its own.
    let with = store_dir(&[
        ("a.md", "rides"),
        ("index.md", "catalog"),
        ("sub/index.md", "catalog2"),
        (".sevralocal", "ghost.md\n"),
    ]);
    let without = store_dir(&[("a.md", "rides"), ("index.md", "catalog")]);
    let (base, log, handle) = mock_hub(vec![
        (200, r#"{"indexed":{"documents":1}}"#.to_string()),
        (200, r#"{"indexed":{"documents":2}}"#.to_string()),
    ]);
    sevra()
        .args(["push", with.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "2 derived catalog(s) kept home (the hub rebuilds its own)",
        ));
    sevra()
        .args(["push", without.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success()
        .stdout(predicate::str::contains("kept home").not());
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert!(
        !reqs[0].body.contains("index.md"),
        "catalogs stay home while the list is active: {}",
        reqs[0].body
    );
    assert!(
        reqs[1].body.contains("index.md"),
        "no list, catalogs ride as before: {}",
        reqs[1].body
    );
}

#[test]
fn a_sevralocal_covering_hub_files_refuses_push_and_quarantine() {
    // The compiled set is evaluated against the two must-ride names, which
    // also catches broad globs like `**`. Push fails before any network I/O;
    // quarantine fails before any write.
    for entry in ["**\n", "DB.md\n", "assets.jsonl\n"] {
        let t = store_dir(&[("a.md", "x"), (".sevralocal", entry)]);
        sevra()
            .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
            .env("SEVRA_HUB_URL", "http://localhost:9")
            .env("SEVRA_API_KEY", "x")
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("ride every push")
                    .and(predicate::str::contains("hub unreachable").not()),
            );
        sevra()
            .args(["secrets", "quarantine", t.path().to_str().unwrap()])
            .assert()
            .failure()
            .stderr(predicate::str::contains("ride every push"));
    }
}

#[test]
fn push_empty_after_exclusion_names_the_kept_home_count() {
    let t = store_dir(&[("private.md", "stays"), (".sevralocal", "private.md\n")]);
    sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("all 1 file(s) are kept home (.sevralocal)")
                .and(predicate::str::contains("hub unreachable").not()),
        );
}

#[test]
fn push_shrink_refusal_notes_kept_home_documents() {
    let t = store_dir(&[
        ("a.md", "rides"),
        ("kept.md", "stays"),
        (".sevralocal", "kept.md\n"),
    ]);
    let (base, _log, handle) = mock_hub(vec![(
        409,
        r#"{"error":"replacing 3 documents with 1 shrinks this brain","code":"shrink_refused"}"#
            .to_string(),
    )]);
    sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("retry with --force").and(predicate::str::contains(
                "(1 document(s) are kept home by .sevralocal and not part of this push)",
            )),
        );
    handle.join().unwrap();
}

#[test]
fn secrets_scan_is_clean_exit_zero_and_hits_exit_one_in_the_push_shape() {
    // Clean store: exit 0, no login, no network.
    let clean = store_dir(&[("a.md", "notes about rotating keys")]);
    sevra()
        .args(["secrets", "scan", clean.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "no matches for known secret formats across 1 file(s)",
        ));
    // Hits: exit 1, the push-refusal shape, minus the push framing.
    let key = format!("AKIA{}", "D".repeat(16));
    let dirty = store_dir(&[("creds.md", &format!("k: {key}"))]);
    for json in [false, true] {
        let mut c = sevra();
        c.args(["secrets", "scan", dirty.path().to_str().unwrap()]);
        if json {
            c.arg("--json");
        }
        let out = c.output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        let all = all_output(&out);
        assert!(!all.contains(&key), "value must never print: {all}");
        assert!(!all.contains("push refused"), "no push framing: {all}");
        assert!(
            all.contains("AWS access key id") && all.contains("creds.md"),
            "names the hit: {all}"
        );
        assert!(all.contains("secrets quarantine"), "names the exit: {all}");
        if json {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for field in ["\"secretHits\"", "\"inPath\"", "\"total\"", "\"error\""] {
                assert!(stdout.contains(field), "missing {field}: {stdout}");
            }
        }
    }
}

#[test]
fn secrets_scan_respects_kept_home_files() {
    // A hit inside a kept-home file is not a push problem — scan sees what a
    // push would carry, and says what it skipped.
    let key = format!("AKIA{}", "E".repeat(16));
    let t = store_dir(&[
        ("a.md", "clean"),
        ("vault.md", &format!("k: {key}")),
        (".sevralocal", "vault.md\n"),
    ]);
    sevra()
        .args(["secrets", "scan", t.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("no matches"))
        .stderr(predicate::str::contains("1 file(s) kept home"));
}

#[test]
fn secrets_quarantine_marks_hits_and_reruns_append_nothing() {
    let key = format!("AKIA{}", "F".repeat(16));
    let t = store_dir(&[("a.md", "clean"), ("creds.md", &format!("k: {key}"))]);
    let list = t.path().join(".sevralocal");
    let out = sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let all = all_output(&out);
    assert!(
        all.contains("kept home (.sevralocal): 1 file(s)") && all.contains("creds.md"),
        "reports the mark: {all}"
    );
    assert!(
        all.contains("forward-only") && all.contains("erases nothing"),
        "states the forward-only truth: {all}"
    );
    assert!(!all.contains(&key), "value must never print: {all}");
    assert_eq!(
        std::fs::read_to_string(&list).unwrap(),
        "creds.md\n",
        "exact path, single trailing newline"
    );
    // Idempotent: the re-run appends nothing and exits 0.
    let out = sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let all = all_output(&out);
    assert!(
        all.contains("nothing new to mark")
            && all.contains("1 hit file(s) already covered by .sevralocal"),
        "reports the coverage: {all}"
    );
    assert_eq!(std::fs::read_to_string(&list).unwrap(), "creds.md\n");
    // And the push preflight now reads clean.
    sevra()
        .args(["secrets", "scan", t.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn secrets_quarantine_dry_run_previews_in_both_modes_and_writes_nothing() {
    let key = format!("AKIA{}", "G".repeat(16));
    let t = store_dir(&[("creds.md", &format!("k: {key}"))]);
    sevra()
        .args([
            "secrets",
            "quarantine",
            t.path().to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "would keep home (.sevralocal): 1 file(s)",
        ));
    let out = sevra()
        .args([
            "secrets",
            "quarantine",
            t.path().to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for field in [
        "\"marked\"",
        "\"closureMarked\"",
        "\"alreadyCovered\"",
        "\"warnings\"",
        "\"total\"",
        "\"note\"",
    ] {
        assert!(stdout.contains(field), "missing {field}: {stdout}");
    }
    assert!(stdout.contains("creds.md"), "names the file: {stdout}");
    assert!(stdout.contains("forward-only"), "the note field: {stdout}");
    assert!(
        !t.path().join(".sevralocal").exists(),
        "--dry-run writes nothing"
    );
}

#[test]
fn secrets_quarantine_never_marks_the_hub_files() {
    // A hit inside DB.md or assets.jsonl is an edit case: they ride every
    // push, so marking them would manufacture the structural refusal.
    let key = format!("AKIA{}", "H".repeat(16));
    let slack = format!("xoxb-{}", "8".repeat(10));
    let t = store_dir(&[
        ("DB.md", &format!("config with {key}")),
        ("assets.jsonl", &format!("{{\"note\":\"{slack}\"}}")),
        ("a.md", "clean"),
    ]);
    let out = sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let all = all_output(&out);
    assert!(all.contains("nothing new to mark"), "{all}");
    assert!(
        all.contains("rides every push") && all.contains("never marked"),
        "warns about the must-ride files: {all}"
    );
    assert!(
        !all.contains(&key) && !all.contains(&slack),
        "no echo: {all}"
    );
    assert!(
        !t.path().join(".sevralocal").exists(),
        "must-ride hits alone create no list"
    );
}

#[test]
fn secrets_quarantine_redacts_filename_secrets_but_writes_the_exact_path() {
    let token = format!("ghp_{}", "b".repeat(36));
    let t = store_dir(&[(&format!("{token}.md"), "clean content")]);
    let out = sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let all = all_output(&out);
    assert!(
        !all.contains(&token),
        "the token filename must never print: {all}"
    );
    assert!(
        all.contains('\u{2026}'),
        "shows the redacted spelling: {all}"
    );
    assert!(
        all.contains("the filename itself is the secret") && all.contains("consider renaming"),
        "warns about the name: {all}"
    );
    // The list needs the EXACT path to match the file — it lives in the
    // store and never uploads.
    let list = std::fs::read_to_string(t.path().join(".sevralocal")).unwrap();
    assert_eq!(list, format!("{token}.md\n"));
    // And the marked file is now covered: a scoped scan reads clean.
    sevra()
        .args(["secrets", "scan", t.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn secrets_quarantine_warns_when_the_manifest_names_kept_home_files() {
    // The manifest rides every push; entries under kept-home paths are the
    // operator's deliberate edit. Malformed JSONL lines are tolerated.
    let t = store_dir(&[
        ("a.md", "clean"),
        (
            "assets.jsonl",
            "{\"path\":\"private/img.png\",\"sha256\":\"x\"}\nnot json at all\n{\"path\":\"public/img.png\"}\n",
        ),
        (".sevralocal", "private/**\n"),
    ]);
    let out = sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let all = all_output(&out);
    assert!(
        all.contains("assets.jsonl names private/img.png") && all.contains("deliberate edit"),
        "warns with the named path: {all}"
    );
    assert!(
        !all.contains("public/img.png"),
        "a riding asset is no warning: {all}"
    );
    assert_eq!(
        std::fs::read_to_string(t.path().join(".sevralocal")).unwrap(),
        "private/**\n",
        "warnings are reported, never acted on"
    );
}

// The closure tests fake `dbmd` with a shell script on PATH (unix-only, the
// same #[cfg(unix)] posture as the store's symlink test).
#[cfg(unix)]
fn fake_dbmd(bin_dir: &std::path::Path, emit_json: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = bin_dir.join("dbmd");
    // `echo` is a sh builtin: the script works even though PATH holds only
    // the fake bin dir (the canned JSON carries no quotes echo would eat).
    std::fs::write(&path, format!("#!/bin/sh\necho '{emit_json}'\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn secrets_quarantine_closure_marks_the_linked_component() {
    let key = format!("AKIA{}", "J".repeat(16));
    let t = store_dir(&[
        ("creds.md", &format!("k: {key}")),
        ("linked.md", "clean, but attached"),
        ("unrelated.md", "clean and free"),
    ]);
    let bin = tempfile::tempdir().unwrap();
    fake_dbmd(
        bin.path(),
        r#"{"store":".","files":[{"path":"creds.md","links":["linked.md"]},{"path":"linked.md","links":[]},{"path":"unrelated.md","links":[]}],"summary":{"files":3,"sources":0,"records":3}}"#,
    );
    let out = sevra()
        .args([
            "secrets",
            "quarantine",
            t.path().to_str().unwrap(),
            "--closure",
        ])
        .env("PATH", bin.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let all = all_output(&out);
    assert!(
        all.contains("closure added 1 linked file(s)") && all.contains("linked.md"),
        "prints every path closure adds: {all}"
    );
    assert_eq!(
        std::fs::read_to_string(t.path().join(".sevralocal")).unwrap(),
        "creds.md\nlinked.md\n",
        "hit + its component, sorted; the free file stays"
    );
}

#[cfg(unix)]
#[test]
fn secrets_quarantine_closure_without_dbmd_fails_before_writing() {
    let key = format!("AKIA{}", "K".repeat(16));
    let t = store_dir(&[("creds.md", &format!("k: {key}"))]);
    let empty_bin = tempfile::tempdir().unwrap();
    sevra()
        .args([
            "secrets",
            "quarantine",
            t.path().to_str().unwrap(),
            "--closure",
        ])
        .env("PATH", empty_bin.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("--closure needs dbmd")
                .and(predicate::str::contains("www.sevrahq.com/install")),
        );
    assert!(
        !t.path().join(".sevralocal").exists(),
        "a missing dbmd must fail before anything is written"
    );
}

#[test]
fn mcp_without_a_credential_serves_public_reads_unauthenticated() {
    let (base, log, handle) = mock_hub(vec![(200, r#"{"brains":[]}"#.to_string())]);
    let out = sevra()
        .arg("mcp")
        .env("SEVRA_HUB_URL", &base)
        .write_stdin(concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_brains","arguments":{}}}"#,
            "\n"
        ))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].authorization, None,
        "no credential → no bearer, not an empty one"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("public brains"),
        "warns that only public brains are reachable"
    );
}

// --- asset byte sync (push) and restore (export) ------------------------------
// The manifest rides the snapshot; the BYTES ride the content-addressed flow
// after commit. sha256("BLOB") below is the fixture blob's real hash — the
// mock hub echoes it so list → presign → PUT → confirm exercises the whole
// client contract, loopback-only, zero new dev-deps.

const BLOB_SHA: &str = "671a0d168d8e3d31819402ac7c3a3cc0abedebbf6a4cda26deacd89724bd6bdc";

fn asset_store() -> tempfile::TempDir {
    store_dir(&[
        ("a.md", "---\ntype: note\nsummary: a\nassets:\n  - _files/x.bin\n---\nalpha\n"),
        (
            "assets.jsonl",
            // dbmd's manifest line shape: path + sha256 + bytes.
            "{\"path\":\"_files/x.bin\",\"sha256\":\"671a0d168d8e3d31819402ac7c3a3cc0abedebbf6a4cda26deacd89724bd6bdc\",\"bytes\":4}\n",
        ),
        ("_files/x.bin", "BLOB"),
    ])
}

#[test]
fn push_syncs_missing_assets_after_commit() {
    let t = asset_store();
    let missing = format!(
        r#"{{"assets":[{{"path":"_files/x.bin","sha256":"{BLOB_SHA}","bytes":4,"required":true,"presentInR2":false}}],"truncated":false}}"#
    );
    let presigned =
        r#"{"url":"{BASE}/blob-put","method":"PUT","reservationId":"01hzy3v7q8r9s0t1v2w3x4y5z7"}"#;
    let (base, log, handle) = mock_hub(vec![
        (200, r#"{"indexed":{"documents":1,"assets":1}}"#.to_string()),
        (200, missing),
        (200, presigned.to_string()),
        (200, "{}".to_string()), // the presigned PUT itself
        (200, r#"{"present":true}"#.to_string()),
    ]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "push failed: {}", all_output(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("assets: 1 uploaded"),
        "upload tally shown: {stdout}"
    );
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 5, "push, list, presign, PUT, confirm: {reqs:?}");
    assert_eq!(reqs[1].path, "/api/hub/brains/b/assets?status=missing");
    assert_eq!(
        reqs[2].path,
        format!("/api/hub/brains/b/assets/presign?sha256={BLOB_SHA}&action=put")
    );
    assert_eq!(reqs[3].method, "PUT");
    assert_eq!(reqs[3].path, "/blob-put");
    assert_eq!(reqs[3].body, "BLOB", "the exact blob bytes ride the PUT");
    assert_eq!(reqs[4].path, "/api/hub/brains/b/assets/confirm");
    assert!(
        reqs[4].body.contains(BLOB_SHA) && reqs[4].body.contains("01hzy3v7q8r9s0t1v2w3x4y5z7"),
        "confirm carries hash + reservation: {}",
        reqs[4].body
    );
}

#[test]
fn push_skip_assets_makes_no_asset_requests() {
    let t = asset_store();
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"indexed":{"documents":1,"assets":1}}"#.to_string(),
    )]);
    sevra()
        .args([
            "push",
            t.path().to_str().unwrap(),
            "--brain",
            "b",
            "--skip-assets",
        ])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success();
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1, "push only, no asset traffic: {reqs:?}");
}

#[test]
fn export_restores_missing_assets_sha_verified() {
    let manifest_line =
        "{\\\"path\\\":\\\"_files/x.bin\\\",\\\"sha256\\\":\\\"671a0d168d8e3d31819402ac7c3a3cc0abedebbf6a4cda26deacd89724bd6bdc\\\",\\\"bytes\\\":4}\\n";
    let export_body = format!(
        r#"{{"slug":"b","files":[{{"path":"a.md","content":"alpha"}},{{"path":"assets.jsonl","content":"{manifest_line}"}}]}}"#
    );
    let presigned = r#"{"url":"{BASE}/blob-get"}"#;
    let (base, log, handle) = mock_hub(vec![
        (200, export_body),
        (200, presigned.to_string()),
        (200, "BLOB".to_string()), // the presigned GET body
    ]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "export failed: {}", all_output(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("assets: 1 restored"),
        "restore tally shown: {stdout}"
    );
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 3, "export, presign, GET: {reqs:?}");
    assert_eq!(
        reqs[1].path,
        format!("/api/hub/brains/b/assets/presign?sha256={BLOB_SHA}&action=get")
    );
    let restored = std::fs::read(work.path().join("out/_files/x.bin")).unwrap();
    assert_eq!(restored, b"BLOB", "restored bytes match the manifest hash");
}
