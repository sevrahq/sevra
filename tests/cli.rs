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
