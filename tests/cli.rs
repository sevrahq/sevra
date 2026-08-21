//! Offline behavior tests (assert_cmd) — the invariants that must hold with no
//! network: version shape, help, flag parsing, the not-logged-in path, the
//! HTTPS guard, and the --json error contract. The live hub parity proof is
//! the platform repo's hub-demo battery driven with SEVRA_BIN.

use assert_cmd::Command;
use base64::Engine as _;
use predicates::prelude::*;
use sha2::{Digest, Sha256};

fn sevra() -> Command {
    let mut c = Command::cargo_bin("sevra").unwrap();
    // Isolate the home dir so no real ~/.sevra credential leaks in.
    // `home::home_dir()` reads HOME on unix and USERPROFILE on Windows —
    // set both so the isolation holds on every CI OS.
    let home = std::env::temp_dir().join(format!("sevra-test-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
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
    let out = sevra().arg("--help").output().unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let help = String::from_utf8(out.stdout).unwrap();
    assert!(
        help.contains("login")
            && help.contains("runs")
            && help.contains("run")
            && help.contains("update")
    );
    assert!(
        help.lines().count() > 5,
        "trusted clap layout must retain its real line breaks"
    );
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

#[cfg(unix)]
#[test]
fn logout_never_deletes_through_a_symlinked_config_directory() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("config.json"), b"UNRELATED").unwrap();
    std::os::unix::fs::symlink(outside.path(), home.path().join(".sevra")).unwrap();

    let out = sevra_at_home(home.path()).arg("logout").output().unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert_eq!(
        std::fs::read(outside.path().join("config.json")).unwrap(),
        b"UNRELATED",
        "logout must not follow ~/.sevra onto an unrelated config.json"
    );
    assert!(
        all_output(&out).contains("could not remove"),
        "{}",
        all_output(&out)
    );
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
                .and(predicate::str::contains("get"))
                .and(predicate::str::contains("rm"))
                .and(predicate::str::contains("delete"))
                .and(predicate::str::contains("scan"))
                .and(predicate::str::contains("quarantine"))
                .and(predicate::str::contains("adopt")),
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
    // ^[A-Za-z][A-Za-z0-9_-]{0,63}$ mirrored client-side. Names are public metadata,
    // so clap echoing them is fine.
    let over = "A".repeat(65);
    for bad in ["1LEADING", "_LEAD", "HAS SPACE", ".DOT", over.as_str()] {
        sevra()
            .args(["secrets", "set", "b", bad])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("vault names"));
    }
    // rm validates too, and the usage error honors --json on stdout.
    sevra()
        .args(["secrets", "rm", "b", "bad.name", "--json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"error\""));

    // Human-friendly and function-binding shapes are both valid.
    for good in ["stripe-key", "STRIPE_KEY", "Key_2"] {
        sevra()
            .args(["secrets", "get", "b", good])
            .env("SEVRA_HUB_URL", "http://localhost:9")
            .env("SEVRA_API_KEY", "x")
            .assert()
            .failure()
            .stderr(predicate::str::contains("hub unreachable"));
    }
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
    // >256 KiB is refused client-side, naming the byte size, never the bytes.
    let big = "x".repeat(256 * 1024 + 1);
    let out = sevra()
        .args(["secrets", "set", "b", "API_KEY"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .write_stdin(big.clone())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = all_output(&out);
    assert!(all.contains("262144"), "should name the cap: {all}");
    assert!(all.contains("262145"), "should name the actual size: {all}");
    assert!(
        !all.contains("xxxxxxxx"),
        "value bytes echoed into output: {all}"
    );

    // The byte-level ceiling fires before UTF-8 decoding/character counting,
    // bounding memory even when a hostile producer never sends a newline.
    let byte_flood = "x".repeat(256 * 1024 + 3);
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
fn secrets_list_get_and_rm_hold_the_error_contract() {
    // Wiring smoke: all route through the hub client, honoring --json.
    sevra()
        .args(["secrets", "list", "b", "--json"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"error\""));
    sevra()
        .args(["secrets", "get", "b", "API_KEY", "--json"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"error\""));
    sevra()
        .args(["secrets", "rm", "b", "API_KEY"])
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
        202 => "Accepted",
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

#[test]
fn agents_and_runs_have_distinct_truthful_surfaces_and_run_posts_the_agent() {
    let (base, log, handle) = mock_hub(vec![
        (
            200,
            r#"{"execution":{"automaticSchedulesEnabled":false,"automaticSchedulesStatus":"temporarily_disabled","manualRunsEnabled":true},"configurationIssues":[{"sourceDocPath":"records/broken.md","message":"agent name is required"}],"agents":[{"name":"curate\u001b[31m","engine":"sevra","enabled":true,"schedule":"0 3 * * *","model":"claude-haiku-4-5-20251001","sourceDocPath":"records/agent.md","flags":[]}],"runs":[],"billing":{"balanceCents":500,"sevraRunsPaused":false}}"#.to_string(),
        ),
        (
            200,
            r#"{"execution":{"automaticSchedulesEnabled":false,"automaticSchedulesStatus":"temporarily_disabled","manualRunsEnabled":true},"agents":[],"runs":[{"id":"01run","agent":"curate\u001b[31m","trigger":"manual","status":"failed","queuedAt":"2026-08-19T12:00:00.000Z","creditsDebitedCents":2,"error":"model unavailable\u001b[31m","outcome":null}],"billing":{"balanceCents":498,"sevraRunsPaused":false}}"#.to_string(),
        ),
        (
            202,
            r#"{"status":"queued","runId":"01test"}"#.to_string(),
        ),
    ]);

    let agents = sevra()
        .args(["agents", "brain"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(agents.status.success(), "{}", all_output(&agents));
    assert!(!agents.stdout.contains(&0x1b));
    let human = String::from_utf8(agents.stdout).unwrap();
    assert!(
        human.contains("automatic schedules are temporarily off"),
        "{human}"
    );
    assert!(
        human.contains("manual only; saved schedule 0 3 * * * is temporarily off"),
        "{human}"
    );
    assert!(human.contains("records/agent.md"), "{human}");
    assert!(
        human.contains("configuration issue in records/broken.md"),
        "{human}"
    );

    let listed = sevra()
        .args(["runs", "brain"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(listed.status.success(), "{}", all_output(&listed));
    assert!(!listed.stdout.contains(&0x1b));
    let history = String::from_utf8(listed.stdout).unwrap();
    assert!(history.contains("failed"), "{history}");
    assert!(history.contains("model unavailable"), "{history}");
    assert!(history.contains("2c debited"), "{history}");

    let queued = sevra()
        .args(["run", "brain", "curate"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(queued.status.success(), "{}", all_output(&queued));
    assert!(all_output(&queued).contains("queued curate manually on brain"));

    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/api/hub/brains/brain/runs");
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].path, "/api/hub/brains/brain/runs");
    assert_eq!(requests[2].method, "POST");
    assert_eq!(requests[2].path, "/api/hub/brains/brain/runs");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&requests[2].body).unwrap(),
        serde_json::json!({ "agent": "curate" })
    );
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

#[test]
fn brain_vault_set_list_get_and_rm_round_trip_bytes() {
    let (base, log, handle) = mock_hub(vec![
        (
            200,
            r#"{"ok":true,"name":"stripe-key","created":true,"updatedAt":"2026-08-10T00:00:00.000Z"}"#
                .to_string(),
        ),
        (
            200,
            r#"{"items":[{"name":"stripe-key","updatedAt":"2026-08-10T00:00:00.000Z"}]}"#
                .to_string(),
        ),
        (
            200,
            r#"{"name":"stripe-key","valueBase64":"AAECCv8=","encoding":"base64"}"#
                .to_string(),
        ),
        (200, r#"{"ok":true,"name":"stripe-key"}"#.to_string()),
    ]);

    let set = sevra()
        .args(["secrets", "set", "brain", "stripe-key"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .write_stdin(vec![0, 1, 2, 10, 255, 0])
        .output()
        .unwrap();
    assert!(set.status.success(), "set: {}", all_output(&set));
    assert!(
        !all_output(&set).contains("AAECCv8A"),
        "set must not echo encoded secret material"
    );

    let list = sevra()
        .args(["secrets", "list", "brain"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(list.status.success(), "list: {}", all_output(&list));
    assert!(all_output(&list).contains("stripe-key"));

    let get = sevra()
        .args(["secrets", "get", "brain", "stripe-key"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(get.status.success(), "get: {}", all_output(&get));
    assert_eq!(get.stdout, vec![0, 1, 2, 10, 255]);
    assert!(get.stderr.is_empty(), "pipe output stays clean");

    let rm = sevra()
        .args(["secrets", "rm", "brain", "stripe-key"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(rm.status.success(), "rm: {}", all_output(&rm));

    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 4);
    assert_eq!(reqs[0].method, "PUT");
    assert_eq!(reqs[0].path, "/api/hub/brains/brain/vault");
    let set_body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
    assert_eq!(set_body["name"], "stripe-key");
    assert_eq!(set_body["valueBase64"], "AAECCv8A");
    assert!(!reqs[0].body.contains("TOPSECRET"));
    assert_eq!(reqs[1].path, "/api/hub/brains/brain/vault");
    assert_eq!(reqs[2].path, "/api/hub/brains/brain/vault?name=stripe-key");
    assert_eq!(reqs[3].method, "DELETE");
    assert_eq!(reqs[3].path, "/api/hub/brains/brain/vault");
    let expected_auth = format!("Bearer {MOCK_KEY}");
    assert!(
        reqs.iter()
            .all(|request| { request.authorization.as_deref() == Some(expected_auth.as_str()) }),
        "every vault request carries the account credential"
    );
}

#[test]
fn brain_vault_get_requires_reveal_on_a_terminal() {
    for json in [false, true] {
        let mut command = sevra();
        command.args(["secrets", "get", "brain", "API_KEY"]);
        if json {
            command.arg("--json");
        }
        let output = command
            .env("SEVRA_HUB_URL", "http://localhost:9")
            .env("SEVRA_API_KEY", MOCK_KEY)
            .env("SEVRA_TEST_STDOUT_TTY", "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let all = all_output(&output);
        assert!(all.contains("--reveal"), "{all}");
    }
}

#[test]
fn brain_vault_terminal_reveal_escapes_control_bytes() {
    let (base, _log, handle) = mock_hub(vec![(
        200,
        r#"{"name":"API_KEY","valueBase64":"YWJjG1szMW1wd24=","encoding":"base64"}"#.to_string(),
    )]);
    let output = sevra()
        .args(["secrets", "get", "brain", "API_KEY", "--reveal"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .env("SEVRA_TEST_STDOUT_TTY", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", all_output(&output));
    assert!(!output.stdout.contains(&0x1b));
    let human = String::from_utf8(output.stdout).unwrap();
    assert!(human.contains("API_KEY: abc\\u{001b}[31mpwn"), "{human}");
    handle.join().unwrap();
}

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
fn mcp_start_run_posts_the_exact_agent_with_the_stored_bearer() {
    let (base, log, handle) = mock_hub(vec![(
        202,
        r#"{"status":"queued","runId":"01run"}"#.to_string(),
    )]);
    let out = sevra()
        .arg("mcp")
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "sevra_account_mcp")
        .write_stdin(concat!(
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"start_run","arguments":{"brain":"work","agent":"curator"}}}"#,
            "\n"
        ))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/hub/brains/work/runs");
    assert_eq!(
        reqs[0].authorization.as_deref(),
        Some("Bearer sevra_account_mcp")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reqs[0].body).unwrap(),
        serde_json::json!({ "agent": "curator" })
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#""isError":false"#), "{stdout}");
    assert!(stdout.contains("01run"), "{stdout}");
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

fn add_adopt_baseline(root: &std::path::Path) {
    let baseline = serde_json::json!({
        "version": 1,
        "brainId": "brain-1",
        "brainSlug": "b",
        "headSeq": 0,
        "feedHash": null,
        "packSha256": null,
        "paths": {},
    });
    std::fs::write(
        root.join(".sevra-sync.json"),
        format!("{}\n", serde_json::to_string_pretty(&baseline).unwrap()),
    )
    .unwrap();
}

fn note_markdown(body: &str) -> String {
    format!(
        "---\ntype: note\nid: 01kxrwrfj75t95dccf2vqekzw3\ncreated: 2026-08-10T00:00:00Z\nupdated: 2026-08-10T00:00:00Z\nsummary: Synthetic adoption fixture\n---\n{body}\n"
    )
}

fn operational_markdown(body: &str) -> String {
    format!(
        "---\ntype: integration\nmeta-type: operational\nid: 01kxrww75p5mnhgammsgvzj11c\ncreated: 2026-08-10T00:00:00Z\nupdated: 2026-08-10T00:00:00Z\nsummary: Synthetic workflow record\n---\n{body}\n"
    )
}

fn canonical_base64(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

#[test]
fn push_help_states_incremental_v2_and_legacy_v1_replacement() {
    sevra().args(["push", "--help"]).assert().success().stdout(
        predicate::str::contains("only changed blobs and explicit deletes travel")
            .and(predicate::str::contains(
                "Legacy v1 brains retain whole-store replacement",
            ))
            .and(predicate::str::contains("--force is refused"))
            .and(predicate::str::contains("Legacy v1 only"))
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
        (200, push_response(1, 0, 1)),
        (200, r#"{"id":"brain-1"}"#.to_string()),
        (200, push_response(1, 0, 2)),
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
    assert_eq!(reqs.len(), 3);
    assert_eq!(reqs[0].path, "/api/hub/brains/b/push");
    assert!(
        !reqs[0].body.contains("allow_shrink"),
        "no allow_shrink without --force: {}",
        reqs[0].body
    );
    assert!(
        reqs[2].body.contains(r#""allow_shrink":true"#),
        "--force rides as allow_shrink: {}",
        reqs[2].body
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
    assert!(all.contains("incident policy"), "remediation line: {all}");
    assert!(
        !all.contains("rotate at the issuer"),
        "Sevra must not prescribe issuer action from a pattern match: {all}"
    );
    assert!(
        !all.contains(&key),
        "the matched value must never print: {all}"
    );
    assert!(
        !all.contains("hub unreachable"),
        "the scan must refuse before any request: {all}"
    );
    // The exits, in order: adopt · whole-file quarantine · edit · override.
    let adopt = all.find("secrets adopt").expect("names adopt");
    let quarantine = all.find("secrets quarantine").expect("names quarantine");
    let edit = all.find("edit deliberately").expect("names the edit path");
    let allow = all.find("--allow-secrets").expect("names the override");
    assert!(
        adopt < quarantine && quarantine < edit && edit < allow,
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
        all.contains("symlink in the store"),
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
fn delete_retries_v2_with_an_exact_control_precondition() {
    let (base, log, handle) = mock_hub(vec![
        (
            409,
            r#"{"error":"A mutation_id and exact expected_control_revision are required for permissioned deletion.","code":"precondition_required"}"#.to_string(),
        ),
        (
            200,
            r#"{"id":"01brain","sync":{"currentWriteProfile":"v2"},"permissionView":{"controlRevision":"control:7"}}"#.to_string(),
        ),
        (
            200,
            r#"{"deleted":true,"brain":"01brain","r2Objects":11}"#.to_string(),
        ),
    ]);
    sevra()
        .args(["delete", "workbrain", "--confirm", "workbrain", "--json"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""deleted": true"#));
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 3);
    assert_eq!(
        (reqs[0].method.as_str(), reqs[0].path.as_str()),
        ("DELETE", "/api/hub/brains/workbrain")
    );
    assert_eq!(
        (reqs[1].method.as_str(), reqs[1].path.as_str()),
        ("GET", "/api/hub/brains/workbrain")
    );
    assert_eq!(
        (reqs[2].method.as_str(), reqs[2].path.as_str()),
        ("DELETE", "/api/hub/brains/workbrain")
    );
    let body: serde_json::Value = serde_json::from_str(&reqs[2].body).unwrap();
    assert_eq!(body["confirm"], "workbrain");
    assert_eq!(body["expected_control_revision"], "control:7");
    assert!(
        body["mutation_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("sevra-delete:") && value.len() > 24),
        "mutation id is stable, namespaced, and unguessable: {body}"
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

#[test]
fn human_output_neutralizes_terminal_control_sequences_from_the_hub() {
    let hostile = "name\n\t\u{1b}[31mred\u{1b}[0m\u{1b}]52;c;Y2xpcA==\u{7}\rforged";
    let body = serde_json::json!({
        "brains": [{
            "slug": "safe",
            "id": "01safe",
            "visibility": "private",
            "name": hostile,
        }]
    })
    .to_string();
    let (base, _log, handle) = mock_hub(vec![(200, body)]);
    let out = sevra()
        .arg("brains")
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    assert!(!out.stdout.contains(&0x1b), "ESC reached the terminal");
    assert!(!out.stdout.contains(&0x07), "BEL reached the terminal");
    assert!(!out.stdout.contains(&b'\r'), "CR reached the terminal");
    assert_eq!(
        out.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "only println's trusted final line break may reach the terminal"
    );
    assert_eq!(
        out.stdout.iter().filter(|byte| **byte == b'\t').count(),
        3,
        "the program-authored tabular layout remains readable"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(r"\n\t\u{001b}"),
        "controls are visibly escaped"
    );
    handle.join().unwrap();
}

// --- .sevralocal + secrets scan/quarantine (the 0.2.5 surface) ----------------
// Secrets get a place that is not the hub: a kept-home list the push walk
// honors, a read-only scan, and a quarantine that appends hit files to the
// list. Everything here is offline except the push wiring against mock hubs.

#[test]
fn oversized_sevralocal_refuses_before_network_and_is_not_mutated() {
    let t = store_dir(&[("a.md", "rides")]);
    let scope_path = t.path().join(".sevralocal");
    let original = vec![b'#'; 1024 * 1024 + 1];
    std::fs::write(&scope_path, &original).unwrap();
    let (base, log, handle) = mock_hub(vec![]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert!(all_output(&out).contains("exceeds 1048576 bytes"));
    handle.join().unwrap();
    assert!(log.lock().unwrap().is_empty(), "no request was attempted");
    assert_eq!(
        std::fs::read(scope_path).unwrap(),
        original,
        "rejection must not rewrite local scope"
    );
}

#[test]
fn push_keeps_sevralocal_files_home_and_reports_it() {
    let t = store_dir(&[
        ("a.md", "rides"),
        ("private.md", "stays-home"),
        (".sevralocal", "private.md\n"),
    ]);
    let (base, log, handle) = mock_hub(vec![
        (200, push_response(1, 0, 1)),
        (200, r#"{"id":"brain-1"}"#.to_string()),
        (200, push_response(1, 0, 1)),
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
    assert_eq!(reqs.len(), 3);
    for req in [0, 2].map(|index| &reqs[index]) {
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
        (200, push_response(1, 0, 1)),
        (200, push_response(2, 0, 2)),
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

#[cfg(unix)]
#[test]
fn secrets_quarantine_refuses_a_scope_symlink_without_creating_its_target() {
    let key = format!("AKIA{}", "N".repeat(16));
    let t = store_dir(&[("creds.md", &format!("k: {key}"))]);
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("future-shell-rc");
    std::os::unix::fs::symlink(&target, t.path().join(".sevralocal")).unwrap();

    sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("must not be a symlink"));
    assert!(
        !target.exists(),
        "a dangling external target must never be created"
    );
}

#[cfg(unix)]
#[test]
fn secrets_quarantine_refuses_newline_filenames_before_writing_scope() {
    let key = format!("AKIA{}", "P".repeat(16));
    let hostile_name = "#\ntouch SEVRA_PWNED\n#.md";
    let t = store_dir(&[(hostile_name, &format!("k: {key}"))]);

    sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "matched file path contains control characters",
        ));
    assert!(
        !t.path().join(".sevralocal").exists(),
        "the line-oriented scope file must not be created"
    );
}

#[test]
fn secrets_quarantine_escapes_a_comment_shaped_filename() {
    let key = format!("AKIA{}", "Q".repeat(16));
    let t = store_dir(&[("#creds.md", &format!("k: {key}"))]);

    sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(t.path().join(".sevralocal")).unwrap(),
        "[#]creds.md\n"
    );
    sevra()
        .args(["secrets", "scan", t.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "no matches for known secret formats",
        ));
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
fn fake_v2_dbmd(bin_dir: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = bin_dir.join("dbmd");
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn v2_push_delegates_only_after_the_hub_selects_v2() {
    let store = store_dir(&[("DB.md", "---\ntype: database\n---\n# Test\n")]);
    let bin = tempfile::tempdir().unwrap();
    let args_log = bin.path().join("args");
    fake_v2_dbmd(
        bin.path(),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho '{{\"v\":2,\"brain_id\":\"brain-1\",\"seq\":1,\"applied\":1}}'\n",
            args_log.display()
        ),
    );
    let (base, log, handle) = mock_hub(vec![(
        409,
        r#"{"error":"use v2","code":"v2_sync_required"}"#.to_string(),
    )]);

    let output = sevra()
        .args(["push", store.path().to_str().unwrap(), "--brain", "b"])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()))
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", all_output(&output));
    assert!(store.path().join(".sevra-v2.json").is_file());
    let args = std::fs::read_to_string(args_log).unwrap();
    assert!(args.contains("sync\nb\n--push\n--dir\n.\n"), "{args}");
    assert!(args.contains("--hub"), "{args}");
    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/api/hub/brains/b/push");
}

#[cfg(unix)]
#[test]
fn v2_clone_delegates_after_typed_export_refusal_and_records_identity() {
    let work = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    fake_v2_dbmd(
        bin.path(),
        r#"#!/bin/sh
out=""
prior=""
for arg in "$@"; do
  if [ "$prior" = "--out" ]; then out="$arg"; fi
  prior="$arg"
done
mkdir -p "$out"
printf '%s\n' '# Test' > "$out/DB.md"
printf '%s\n' '{"brain":"brain-1","slug":"b","headSeq":0,"files":1,"dest":"brain","extraLocal":[],"syncStatus":"synced"}'
"#,
    );
    let (base, log, handle) = mock_hub(vec![
        (
            409,
            r#"{"error":"use v2 bulk","code":"v2_bulk_required"}"#.to_string(),
        ),
        (200, r#"{"id":"brain-1","slug":"b"}"#.to_string()),
    ]);

    let output = sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()))
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", all_output(&output));
    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.path().join("brain/.sevra-v2.json")).unwrap())
            .unwrap();
    assert_eq!(marker["brain"], "brain-1");
    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests[0].path, "/api/hub/brains/b/export?format=pack");
    assert_eq!(requests[1].path, "/api/hub/brains/b");
}

#[cfg(unix)]
#[test]
fn v2_export_keeps_the_cross_protocol_file_count_contract() {
    let work = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    fake_v2_dbmd(
        bin.path(),
        r#"#!/bin/sh
out=""
prior=""
for arg in "$@"; do
  if [ "$prior" = "--out" ]; then out="$arg"; fi
  prior="$arg"
done
mkdir -p "$out/records"
printf '%s\n' '# Test' > "$out/DB.md"
printf '%s\n' '# One' > "$out/records/one.md"
printf '%s\n' '{"brain":"brain-1","headSeq":7,"files":2,"dest":"stage","extraLocal":[],"syncStatus":"synced"}'
"#,
    );
    let (base, log, handle) = mock_hub(vec![
        (
            409,
            r#"{"error":"use v2 bulk","code":"v2_bulk_required"}"#.to_string(),
        ),
        (200, r#"{"id":"brain-1","slug":"b"}"#.to_string()),
        (200, r#"{"items":[]}"#.to_string()),
    ]);

    let output = sevra()
        .args(["export", "b", "out", "--json"])
        .current_dir(work.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()))
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", all_output(&output));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["fileCount"], 2);
    assert_eq!(result["files"], 2, "retain the delegated dbmd field");
    assert_eq!(result["headSeq"], 7);
    assert_eq!(
        std::fs::read_to_string(work.path().join("out/records/one.md")).unwrap(),
        "# One\n"
    );
    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].path,
        "/api/hub/brains/b/export?format=pack&includeVaultNames=1"
    );
    assert_eq!(requests[1].path, "/api/hub/brains/b");
    assert_eq!(requests[2].path, "/api/hub/brains/b/vault");
}

#[cfg(unix)]
#[test]
fn v2_push_delegates_exact_withdrawals_and_reason_to_dbmd() {
    let store = store_dir(&[("DB.md", "---\ntype: database\n---\n# Test\n")]);
    let bin = tempfile::tempdir().unwrap();
    let args_log = bin.path().join("args");
    fake_v2_dbmd(
        bin.path(),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho '{{\"v\":2,\"brain_id\":\"brain-1\",\"seq\":2,\"applied\":1}}'\n",
            args_log.display()
        ),
    );
    let (base, _log, handle) = mock_hub(vec![(
        409,
        r#"{"error":"use v2","code":"v2_sync_required"}"#.to_string(),
    )]);
    let output = sevra()
        .args([
            "push",
            store.path().to_str().unwrap(),
            "--brain",
            "b",
            "--withdraw-from-hosting",
            "sources/private.md",
            "--withdraw-reason",
            "approved company retention change",
        ])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()))
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", all_output(&output));
    let args = std::fs::read_to_string(args_log).unwrap();
    assert!(
        args.contains("--withdraw-from-hosting\nsources/private.md\n"),
        "{args}"
    );
    assert!(
        args.contains("--withdraw-reason\napproved company retention change\n"),
        "{args}"
    );
    handle.join().unwrap();
}

#[cfg(unix)]
#[test]
fn alias_rebind_is_a_thin_exact_dbmd_delegation() {
    let bin = tempfile::tempdir().unwrap();
    let args_log = bin.path().join("args");
    fake_v2_dbmd(
        bin.path(),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho '{{\"v\":2,\"outcome\":\"alias_rebound\"}}'\n",
            args_log.display()
        ),
    );
    let output = sevra()
        .args([
            "rebind",
            "company",
            "--from",
            "01j5qc3v9k4ym8rwbn2tqe6f7d",
            "--to",
            "01j5qc3v9k4ym8rwbn2tqe6f7e",
        ])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()))
        .env("SEVRA_HUB_URL", "http://127.0.0.1:9")
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", all_output(&output));
    let args = std::fs::read_to_string(args_log).unwrap();
    assert!(
        args.contains(
            "sync\ncompany\nrebind\n--from\n01j5qc3v9k4ym8rwbn2tqe6f7d\n--to\n01j5qc3v9k4ym8rwbn2tqe6f7e\n"
        ),
        "{args}"
    );
}

#[cfg(unix)]
#[test]
fn push_declares_only_linked_kept_home_names_and_counts_the_rest() {
    let t = store_dir(&[
        (
            "a.md",
            "Riding content links [[private]] twice: [[private]].",
        ),
        ("private.md", "linked but kept home"),
        ("unlinked.md", "never named by riding content"),
        (".sevralocal", "private.md\nunlinked.md\n"),
    ]);
    let bin = tempfile::tempdir().unwrap();
    fake_dbmd(
        bin.path(),
        r#"{"store":".","files":[{"path":"a.md","links":["private.md"]},{"path":"private.md","links":[]},{"path":"unlinked.md","links":[]}],"summary":{"files":3,"sources":0,"records":3}}"#,
    );
    let (base, log, handle) = mock_hub(vec![(200, push_response(1, 0, 1))]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("PATH", bin.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    assert!(all_output(&out)
        .contains("1 withheld target name(s) declared; 1 other kept-home file(s) stay unnamed"));
    handle.join().unwrap();
    let requests = log.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(body["withheld_paths"], serde_json::json!(["private.md"]));
    assert_eq!(body["kept_home_unlinked"], 1);
    assert!(
        !requests[0].body.contains("unlinked.md")
            && !requests[0].body.contains("never named by riding content"),
        "an unlinked kept-home filename or body escaped: {}",
        requests[0].body,
    );
    assert!(
        !requests[0].body.contains("linked but kept home"),
        "withheld metadata may name the target but never carry its body"
    );
}

#[cfg(unix)]
#[test]
fn push_declares_linked_derived_catalogs_as_withheld() {
    let t = store_dir(&[
        (
            "a.md",
            "Riding content links [[sub/index]], while [[missing/index]] is truly absent.",
        ),
        ("index.md", "unlinked generated catalog"),
        ("sub/index.md", "linked generated catalog"),
        // Any active entry keeps generated catalogs home, even when the entry
        // itself matches no file in the store.
        (".sevralocal", "ghost.md\n"),
    ]);
    let bin = tempfile::tempdir().unwrap();
    fake_dbmd(
        bin.path(),
        // Real dbmd emit includes normalized links to generated catalogs but
        // deliberately omits the catalog files themselves from `files`.
        r#"{"store":".","files":[{"path":"a.md","links":["sub/index.md","missing/index.md"]}],"summary":{"files":1,"sources":0,"records":1}}"#,
    );
    let (base, log, handle) = mock_hub(vec![(200, push_response(1, 0, 1))]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("PATH", bin.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    assert!(all_output(&out)
        .contains("1 withheld target name(s) declared; 1 other kept-home file(s) stay unnamed"));
    handle.join().unwrap();

    let requests = log.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(body["withheld_paths"], serde_json::json!(["sub/index.md"]),);
    assert_eq!(body["kept_home_unlinked"], 1);
    assert!(
        !requests[0].body.contains("linked generated catalog")
            && !requests[0].body.contains("unlinked generated catalog"),
        "catalog bodies must stay local: {}",
        requests[0].body,
    );
}

#[cfg(unix)]
#[test]
fn push_with_possible_linked_withholding_refuses_without_dbmd_before_network() {
    let t = store_dir(&[
        ("a.md", "Maybe [[private]]."),
        ("private.md", "kept"),
        (".sevralocal", "private.md\n"),
    ]);
    let empty_bin = tempfile::tempdir().unwrap();
    let (base, log, handle) = mock_hub(vec![]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("PATH", empty_bin.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(all_output(&out).contains("push withheld accounting needs dbmd"));
    handle.join().unwrap();
    assert!(log.lock().unwrap().is_empty(), "no request was attempted");
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

// --- secrets adopt: vault-first, resumable migration -------------------------

#[test]
fn secrets_adopt_uses_v2_checkout_identity_and_refuses_immutable_source_before_vault() {
    let key = format!("AKIA{}", "A".repeat(16));
    let store = store_dir(&[(
        "sources/private.md",
        &format!(
            "---\ntype: note\ncreated: 2026-08-20\nupdated: 2026-08-20\nsummary: evidence\n---\naws key: {key}\n"
        ),
    )]);
    std::fs::write(
        store.path().join(".sevra-v2.json"),
        b"{\"v\":2,\"brain\":\"01j5qc3v9k4ym8rwbn2tqe6f7d\"}\n",
    )
    .unwrap();
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"brain":"01j5qc3v9k4ym8rwbn2tqe6f7d","storageProfile":"v2","document":{"path":"sources/private.md"}}"#.to_string(),
    )]);
    let output = sevra()
        .args(["--json", "secrets", "adopt", store.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let all = all_output(&output);
    assert!(
        all.contains("immutable hosted evidence")
            && all.contains("immutable_source_remediation_required"),
        "{all}"
    );
    assert!(!all.contains(&key), "secret value must never print: {all}");
    assert!(!all.contains("no .sevra-sync.json"), "{all}");
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 1, "must stop before vault: {requests:?}");
    assert_eq!(
        requests[0].path,
        "/api/hub/brains/01j5qc3v9k4ym8rwbn2tqe6f7d/resolve?path=sources%2Fprivate.md"
    );
    drop(requests);
    handle.join().unwrap();
}

#[test]
fn secrets_adopt_deduplicates_rewrites_and_unquarantines_exact_paths() {
    let first = format!("sk-proj-{}", "a".repeat(24));
    let second = format!("ghp_{}", "b".repeat(36));
    let source = note_markdown(&format!("api_key: {first}\nagain: {first}"));
    let record = operational_markdown(&format!(
        "api_key: {second}\nevidence: [[sources/evidence]]\napi_key: {first}"
    ));
    let t = store_dir(&[
        ("sources/evidence.md", &source),
        ("records/config.md", &record),
        (
            ".sevralocal",
            "# exact quarantines from scan\nsources/evidence.md\nrecords/config.md\n",
        ),
    ]);
    add_adopt_baseline(t.path());
    let (base, log, handle) = mock_hub(vec![
        (201, r#"{"ok":true,"created":true}"#.to_string()),
        (201, r#"{"ok":true,"created":true}"#.to_string()),
    ]);
    let out = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap(), "--json"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let shown = all_output(&out);
    assert!(
        !shown.contains(&first) && !shown.contains(&second),
        "{shown}"
    );
    assert!(
        shown.contains("immutable evidence"),
        "source warning: {shown}"
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["distinctValues"], 2);
    assert_eq!(result["replacements"], 4);
    assert_eq!(result["unquarantinedEntries"], 2);

    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 2, "same value is committed only once");
    assert!(reqs.iter().all(|request| {
        request.method == "POST" && request.path == "/api/hub/brains/brain-1/vault"
    }));
    let mut names = reqs
        .iter()
        .map(|request| {
            serde_json::from_str::<serde_json::Value>(&request.body).unwrap()["name"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names.len(), 2);
    assert!(names.iter().any(|name| name == "API_KEY"));
    assert!(names.iter().any(|name| name.starts_with("API_KEY_")));
    drop(reqs);

    for path in ["sources/evidence.md", "records/config.md"] {
        let content = std::fs::read_to_string(t.path().join(path)).unwrap();
        assert!(!content.contains(&first) && !content.contains(&second));
        assert!(content.contains("redacted: ["), "{path}: {content}");
        assert!(content.contains("$API_KEY"), "{path}: {content}");
    }
    assert_eq!(
        std::fs::read_to_string(t.path().join(".sevralocal")).unwrap(),
        "# exact quarantines from scan\n"
    );
    assert!(!t.path().join(".sevra-adopt.json").exists());

    // A completed migration is idempotent and needs no hub round trip.
    let rerun = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(rerun.status.success(), "{}", all_output(&rerun));
    assert!(all_output(&rerun).contains("no adoptable markdown credentials remain"));
}

#[test]
fn secrets_adopt_kill_between_vault_and_file_is_safely_resumable() {
    let token = format!("sk-proj-{}", "c".repeat(24));
    let markdown = note_markdown(&format!("api_key: {token}"));
    let t = store_dir(&[
        ("sources/credential.md", &markdown),
        (".sevralocal", "sources/credential.md\n"),
    ]);
    add_adopt_baseline(t.path());

    let (first_base, first_log, first_handle) =
        mock_hub(vec![(201, r#"{"ok":true,"created":true}"#.to_string())]);
    let first = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &first_base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .env("SEVRA_TEST_ADOPT_EXIT_AFTER_VAULT", "1")
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(86), "{}", all_output(&first));
    first_handle.join().unwrap();
    assert_eq!(first_log.lock().unwrap().len(), 1);
    assert_eq!(
        std::fs::read_to_string(t.path().join("sources/credential.md")).unwrap(),
        markdown,
        "vault commit happens before the first literal is removed"
    );
    assert!(t.path().join(".sevra-adopt.json").exists());
    assert_eq!(
        std::fs::read_to_string(t.path().join(".sevralocal")).unwrap(),
        "sources/credential.md\n"
    );

    let encoded = canonical_base64(token.as_bytes());
    let (resume_base, resume_log, resume_handle) = mock_hub(vec![
        (
            409,
            r#"{"error":"exists","code":"vault_item_exists"}"#.to_string(),
        ),
        (
            200,
            format!(r#"{{"name":"API_KEY","valueBase64":"{encoded}"}}"#),
        ),
    ]);
    let resumed = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &resume_base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(resumed.status.success(), "{}", all_output(&resumed));
    assert!(!all_output(&resumed).contains(&token));
    resume_handle.join().unwrap();
    let reqs = resume_log.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[1].method, "GET");
    drop(reqs);
    let content = std::fs::read_to_string(t.path().join("sources/credential.md")).unwrap();
    assert!(!content.contains(&token));
    assert!(content.contains("$API_KEY"));
    assert!(!t.path().join(".sevra-adopt.json").exists());
}

#[test]
fn secrets_adopt_resumes_after_one_of_several_files_was_rewritten() {
    let token = format!("sk-proj-{}", "d".repeat(24));
    let first_markdown = operational_markdown(&format!("api_key: {token}"));
    let second_markdown = note_markdown(&format!("api_key: {token}"));
    let t = store_dir(&[
        ("records/a.md", &first_markdown),
        ("sources/b.md", &second_markdown),
        (".sevralocal", "records/a.md\nsources/b.md\n"),
    ]);
    add_adopt_baseline(t.path());
    let (first_base, _, first_handle) =
        mock_hub(vec![(201, r#"{"ok":true,"created":true}"#.to_string())]);
    let first = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &first_base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .env("SEVRA_TEST_ADOPT_EXIT_AFTER_FILE", "1")
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(87), "{}", all_output(&first));
    first_handle.join().unwrap();
    let states = ["records/a.md", "sources/b.md"].map(|path| {
        std::fs::read_to_string(t.path().join(path))
            .unwrap()
            .contains(&token)
    });
    assert_ne!(states[0], states[1], "exactly one file was committed");

    let encoded = canonical_base64(token.as_bytes());
    let (resume_base, _, resume_handle) = mock_hub(vec![
        (
            409,
            r#"{"error":"exists","code":"vault_item_exists"}"#.to_string(),
        ),
        (
            200,
            format!(r#"{{"name":"API_KEY","valueBase64":"{encoded}"}}"#),
        ),
    ]);
    let resumed = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &resume_base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(resumed.status.success(), "{}", all_output(&resumed));
    resume_handle.join().unwrap();
    for path in ["records/a.md", "sources/b.md"] {
        let content = std::fs::read_to_string(t.path().join(path)).unwrap();
        assert!(!content.contains(&token));
        assert!(content.contains("$API_KEY"));
    }
    assert!(!t.path().join(".sevra-adopt.json").exists());
}

#[test]
fn secrets_adopt_never_overwrites_a_different_existing_vault_value() {
    let token = format!("sk-proj-{}", "e".repeat(24));
    let other = format!("sk-proj-{}", "f".repeat(24));
    let markdown = operational_markdown(&format!("api_key: {token}"));
    let t = store_dir(&[("records/config.md", &markdown)]);
    add_adopt_baseline(t.path());
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let expected = format!("API_KEY_{}", &hash[..8]);
    let (base, log, handle) = mock_hub(vec![
        (
            409,
            r#"{"error":"exists","code":"vault_item_exists"}"#.to_string(),
        ),
        (
            200,
            format!(
                r#"{{"name":"API_KEY","valueBase64":"{}"}}"#,
                canonical_base64(other.as_bytes())
            ),
        ),
        (201, r#"{"ok":true,"created":true}"#.to_string()),
    ]);
    let out = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    let first: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
    let retry: serde_json::Value = serde_json::from_str(&reqs[2].body).unwrap();
    assert_eq!(first["name"], "API_KEY");
    assert_eq!(retry["name"], expected);
    assert_eq!(reqs[1].path, "/api/hub/brains/brain-1/vault?name=API_KEY");
    drop(reqs);
    let content = std::fs::read_to_string(t.path().join("records/config.md")).unwrap();
    assert!(content.contains(&format!("${expected}")));
    assert!(!content.contains(&token));
}

#[test]
fn secrets_adopt_refuses_asset_hits_before_vault_access() {
    let token = format!("ghp_{}", "g".repeat(36));
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let manifest = format!(
        "{{\"path\":\"_files/secret.txt\",\"sha256\":\"{hash}\",\"bytes\":{}}}\n",
        token.len()
    );
    let clean = operational_markdown("no credential here");
    let t = store_dir(&[
        ("records/clean.md", &clean),
        ("assets.jsonl", &manifest),
        ("_files/secret.txt", &token),
    ]);
    add_adopt_baseline(t.path());
    let (base, log, handle) = mock_hub(vec![]);
    let out = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let shown = all_output(&out);
    assert!(
        shown.contains("outside editable markdown content"),
        "{shown}"
    );
    assert!(!shown.contains(&token), "asset value leaked: {shown}");
    handle.join().unwrap();
    assert!(log.lock().unwrap().is_empty());
    assert!(!t.path().join(".sevra-adopt.json").exists());
}

#[test]
fn secrets_adopt_refuses_an_oversized_pem_before_vault_access() {
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        "A".repeat(256 * 1024)
    );
    let markdown = note_markdown(&format!("private_key: {pem}"));
    let t = store_dir(&[("sources/key.md", &markdown)]);
    add_adopt_baseline(t.path());
    let (base, log, handle) = mock_hub(vec![]);
    let out = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let shown = all_output(&out);
    assert!(
        shown.contains("above the 262144-byte vault item limit"),
        "{shown}"
    );
    assert!(!shown.contains("AAAAAAAA"), "PEM bytes leaked: {shown}");
    handle.join().unwrap();
    assert!(log.lock().unwrap().is_empty());
    assert!(!t.path().join(".sevra-adopt.json").exists());
}

#[test]
fn workflow_shaped_adopt_then_push_has_zero_dangling_source_links() {
    let token = format!("sk-proj-{}", "h".repeat(24));
    let db = "---\ntype: db-md\nscope: synthetic-adopt\nowner: test@sevrahq.com\n---\n\n# Synthetic adoption brain\n";
    let source = note_markdown(&format!("api_key: {token}\nImported workflow evidence."));
    let t = store_dir(&[
        ("DB.md", db),
        ("sources/import.md", &source),
        (".sevralocal", "sources/import.md\n"),
    ]);
    // Workflowy-shaped means one quarantined source with broad fan-in. Keep
    // the fixture generated and synthetic: enough edges to exercise the same
    // topology without ever touching the founder's real brain.
    std::fs::create_dir_all(t.path().join("records/workflows")).unwrap();
    for index in 0..512 {
        let title = format!("Workflow item {index:04}");
        let record = format!(
            "---\ntype: workflow\nmeta-type: operational\ncreated: 2026-08-10T00:00:00Z\nupdated: 2026-08-10T00:00:00Z\nsummary: {title}\n---\n{title}. Evidence: [[sources/import]].\n"
        );
        std::fs::write(
            t.path().join(format!("records/workflows/{index:04}.md")),
            record,
        )
        .unwrap();
    }
    add_adopt_baseline(t.path());
    let (adopt_base, _, adopt_handle) =
        mock_hub(vec![(201, r#"{"ok":true,"created":true}"#.to_string())]);
    let adopted = sevra()
        .args(["secrets", "adopt", t.path().to_str().unwrap()])
        .env("SEVRA_HUB_URL", &adopt_base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(adopted.status.success(), "{}", all_output(&adopted));
    adopt_handle.join().unwrap();

    let (push_base, push_log, push_handle) = mock_hub(vec![
        (200, r#"{"id":"brain-1"}"#.to_string()),
        (200, push_response(513, 0, 1)),
    ]);
    let pushed = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &push_base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(pushed.status.success(), "{}", all_output(&pushed));
    push_handle.join().unwrap();
    let requests = push_log.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
    let files = body["files"]
        .as_array()
        .expect("small push carries JSON files");
    let paths = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(paths.contains("sources/import.md"));
    assert!(paths.contains("records/workflows/0000.md"));
    assert!(paths.contains("records/workflows/0256.md"));
    assert!(paths.contains("records/workflows/0511.md"));
    let hosted = requests[1].body.as_str();
    assert_eq!(hosted.matches("[[sources/import]]").count(), 512);
    assert!(hosted.contains("$API_KEY"));
    assert!(!hosted.contains(&token));
    assert!(!hosted.contains(".sevralocal"));
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
const FEED_ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const FEED_TWO: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn clone_snapshot(seq: u64, feed: &str, content: &str) -> String {
    serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "headSeq": seq,
        "feedHash": feed,
        "files": [{ "path": "a.md", "content": content }],
    })
    .to_string()
}

fn push_response(documents: u64, assets: u64, seq: u64) -> String {
    let feed = if seq == 1 { FEED_ONE } else { FEED_TWO };
    serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "headSeq": seq,
        "feedHash": feed,
        "packSha256": "a".repeat(64),
        "indexed": {
            "documents": documents,
            "edges": 0,
            "resolvedEdges": 0,
            "withheldEdges": 0,
            "brokenEdges": 0,
            "assets": assets
        },
    })
    .to_string()
}

#[test]
fn clone_records_a_baseline_and_clean_pull_is_a_noop() {
    let work = tempfile::tempdir().unwrap();
    let (base, log, handle) = mock_hub(vec![
        (200, clone_snapshot(1, FEED_ONE, "alpha")),
        (
            200,
            format!(r#"{{"id":"brain-1","slug":"b","headSeq":1,"feedHash":"{FEED_ONE}"}}"#),
        ),
    ]);
    let clone = sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(clone.status.success(), "{}", all_output(&clone));
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.path().join("brain/.sevra-sync.json")).unwrap())
            .unwrap();
    assert_eq!(baseline["brainId"], "brain-1");
    assert_eq!(baseline["headSeq"], 1);
    assert!(
        baseline["packSha256"]
            .as_str()
            .is_some_and(|value| value.len() == 64),
        "baseline binds the canonical pack: {baseline}"
    );
    let pull = sevra()
        .args(["pull", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(pull.status.success(), "{}", all_output(&pull));
    assert!(all_output(&pull).contains("already current"));
    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 2, "clone export + cheap head check only");
    assert_eq!(requests[0].path, "/api/hub/brains/b/export?format=pack");
    assert_eq!(requests[1].path, "/api/hub/brains/brain-1");
}

#[cfg(unix)]
#[test]
fn cloned_push_preserves_only_the_hosted_withholding_classification() {
    let work = tempfile::tempdir().unwrap();
    let snapshot = serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "headSeq": 1,
        "feedHash": FEED_ONE,
        "files": [{
            "path": "a.md",
            "content": "Known omission [[private]], genuinely missing [[new]].",
        }],
        "withheldPaths": ["private.md"],
        "keptHomeUnlinked": 4,
    })
    .to_string();
    let bin = tempfile::tempdir().unwrap();
    fake_dbmd(
        bin.path(),
        r#"{"store":".","files":[{"path":"a.md","links":["private.md","new.md"]}],"summary":{"files":1,"sources":0,"records":1}}"#,
    );
    let (base, log, handle) = mock_hub(vec![
        (200, snapshot),
        (200, r#"{"id":"brain-1"}"#.to_string()),
        (200, push_response(1, 0, 2)),
    ]);

    let clone = sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(clone.status.success(), "{}", all_output(&clone));
    assert!(all_output(&clone)
        .contains("1 linked target name(s) and 4 other file(s) remain on the source machine"));
    let cloned_baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.path().join("brain/.sevra-sync.json")).unwrap())
            .unwrap();
    assert_eq!(
        cloned_baseline["withheldPaths"],
        serde_json::json!(["private.md"])
    );
    assert_eq!(cloned_baseline["keptHomeUnlinked"], 4);
    assert_eq!(cloned_baseline["carriedKeptHomeUnlinked"], 4);

    let push = sevra()
        .args(["push", "brain", "--brain", "b", "--skip-assets"])
        .current_dir(work.path())
        .env("PATH", bin.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(push.status.success(), "{}", all_output(&push));
    handle.join().unwrap();

    let requests = log.lock().unwrap();
    let body: serde_json::Value = serde_json::from_str(&requests[2].body).unwrap();
    assert_eq!(body["withheld_paths"], serde_json::json!(["private.md"]));
    assert_eq!(body["kept_home_unlinked"], 4);
    assert!(
        !body["withheld_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == "new.md"),
        "a newly broken target must not inherit trust from the clone baseline",
    );

    let pushed_baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.path().join("brain/.sevra-sync.json")).unwrap())
            .unwrap();
    assert_eq!(pushed_baseline["keptHomeUnlinked"], 4);
    assert_eq!(pushed_baseline["carriedKeptHomeUnlinked"], 4);
}

#[test]
fn clone_restores_declared_assets_only_after_exact_sha_verification() {
    let work = tempfile::tempdir().unwrap();
    let manifest = format!("{{\"path\":\"_files/x.bin\",\"sha256\":\"{BLOB_SHA}\",\"bytes\":4}}\n");
    let snapshot = serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "headSeq": 1,
        "feedHash": FEED_ONE,
        "files": [
            { "path": "a.md", "content": "alpha" },
            { "path": "assets.jsonl", "content": manifest },
        ],
    })
    .to_string();
    let (base, log, handle) = mock_hub(vec![
        (200, snapshot),
        (
            200,
            format!(
                r#"{{"items":[{{"sha256":"{BLOB_SHA}","url":"{{BASE}}/blob-get","method":"GET"}}]}}"#
            ),
        ),
        (200, "BLOB".to_string()),
    ]);
    let clone = sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(clone.status.success(), "{}", all_output(&clone));
    assert_eq!(
        std::fs::read(work.path().join("brain/_files/x.bin")).unwrap(),
        b"BLOB"
    );
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.path().join("brain/.sevra-sync.json")).unwrap())
            .unwrap();
    assert_eq!(baseline["paths"]["_files/x.bin"], BLOB_SHA);
    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].path, "/api/hub/brains/b/assets/transfer");
}

#[test]
fn clone_retries_a_transient_asset_presign_failure_without_leaking_a_partial_root() {
    let work = tempfile::tempdir().unwrap();
    let manifest = format!("{{\"path\":\"_files/x.bin\",\"sha256\":\"{BLOB_SHA}\",\"bytes\":4}}\n");
    let snapshot = serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "headSeq": 1,
        "feedHash": FEED_ONE,
        "files": [
            { "path": "a.md", "content": "alpha" },
            { "path": "assets.jsonl", "content": manifest },
        ],
    })
    .to_string();
    let (base, log, handle) = mock_hub(vec![
        (200, snapshot),
        (0, String::new()),
        (503, r#"{"error":"temporary presign outage"}"#.to_string()),
        (
            200,
            format!(
                r#"{{"items":[{{"sha256":"{BLOB_SHA}","url":"{{BASE}}/blob-get","method":"GET"}}]}}"#
            ),
        ),
        (200, "BLOB".to_string()),
    ]);
    let clone = sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(clone.status.success(), "{}", all_output(&clone));
    assert!(String::from_utf8_lossy(&clone.stderr).contains("planning was interrupted"));
    assert_eq!(
        std::fs::read(work.path().join("brain/_files/x.bin")).unwrap(),
        b"BLOB"
    );
    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[1].path, "/api/hub/brains/b/assets/transfer");
    assert_eq!(requests[1].path, requests[2].path);
    assert_eq!(requests[2].path, requests[3].path);
}

#[test]
fn clone_edit_pull_refuses_locally_before_any_head_request() {
    let work = tempfile::tempdir().unwrap();
    let (base, _, handle) = mock_hub(vec![(200, clone_snapshot(1, FEED_ONE, "alpha"))]);
    sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success();
    handle.join().unwrap();
    std::fs::write(work.path().join("brain/a.md"), "local edit").unwrap();
    let pull = sevra()
        .args(["pull", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", "http://127.0.0.1:9")
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!pull.status.success());
    let output = all_output(&pull);
    assert!(output.contains("local store diverged") && output.contains("a.md"));
    assert!(
        !output.contains("hub unreachable"),
        "local refusal is first: {output}"
    );
    assert_eq!(
        std::fs::read_to_string(work.path().join("brain/a.md")).unwrap(),
        "local edit"
    );
}

#[test]
fn pull_fetches_the_exact_advanced_snapshot_and_force_discards_local_edits() {
    for force in [false, true] {
        let work = tempfile::tempdir().unwrap();
        let (base, log, handle) = mock_hub(vec![
            (200, clone_snapshot(1, FEED_ONE, "alpha")),
            (
                200,
                format!(r#"{{"id":"brain-1","slug":"b","headSeq":2,"feedHash":"{FEED_TWO}"}}"#),
            ),
            (200, clone_snapshot(2, FEED_TWO, "remote beta")),
        ]);
        sevra()
            .args(["clone", "b", "brain"])
            .current_dir(work.path())
            .env("SEVRA_HUB_URL", &base)
            .env("SEVRA_API_KEY", "x")
            .assert()
            .success();
        if force {
            std::fs::write(work.path().join("brain/a.md"), "discard me").unwrap();
        }
        let mut command = sevra();
        command.args(["pull", "brain"]);
        if force {
            command.arg("--force");
        }
        let pull = command
            .current_dir(work.path())
            .env("SEVRA_HUB_URL", &base)
            .env("SEVRA_API_KEY", "x")
            .output()
            .unwrap();
        assert!(pull.status.success(), "{}", all_output(&pull));
        assert_eq!(
            std::fs::read_to_string(work.path().join("brain/a.md")).unwrap(),
            "remote beta"
        );
        let baseline: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.path().join("brain/.sevra-sync.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(baseline["headSeq"], 2);
        handle.join().unwrap();
        let requests = log.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2].path,
            format!("/api/hub/brains/brain-1/export?format=pack&atSeq=2&feedHash={FEED_TWO}")
        );
    }
}

#[test]
fn killed_pull_recovers_the_old_snapshot_before_its_next_request() {
    let work = tempfile::tempdir().unwrap();
    let (clone_base, _, clone_handle) = mock_hub(vec![(200, clone_snapshot(1, FEED_ONE, "alpha"))]);
    sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &clone_base)
        .env("SEVRA_API_KEY", "x")
        .assert()
        .success();
    clone_handle.join().unwrap();

    let mut files = vec![serde_json::json!({ "path": "a.md", "content": "remote beta" })];
    for index in 0..128 {
        files.push(serde_json::json!({
            "path": format!("records/{index:04}.md"),
            "content": format!("remote record {index}"),
        }));
    }
    let snapshot = serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "headSeq": 2,
        "feedHash": FEED_TWO,
        "files": files,
    })
    .to_string();
    let (pull_base, _, pull_handle) = mock_hub(vec![
        (
            200,
            format!(r#"{{"id":"brain-1","slug":"b","headSeq":2,"feedHash":"{FEED_TWO}"}}"#),
        ),
        (200, snapshot),
    ]);

    let home = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sevra"))
        .args(["pull", "brain"])
        .current_dir(work.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("SEVRA_NO_AUTO_UPDATE", "1")
        .env("SEVRA_HUB_URL", &pull_base)
        .env("SEVRA_API_KEY", "x")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let changed = work.path().join("brain/a.md");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if std::fs::read(&changed).is_ok_and(|bytes| bytes == b"remote beta") {
            child.kill().unwrap();
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("pull completed before the kill boundary: {status}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pull never reached its first committed path"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    child.wait().unwrap();
    pull_handle.join().unwrap();

    let brain = work.path().join("brain");
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(brain.join(".sevra-sync.json")).unwrap()).unwrap();
    assert_eq!(baseline["headSeq"], 1, "the baseline is the commit marker");
    assert!(
        brain.join(".sevra-pull-journal.json").exists(),
        "the durable journal survives process death"
    );

    let (recovery_base, recovery_log, recovery_handle) = mock_hub(vec![(
        200,
        format!(r#"{{"id":"brain-1","slug":"b","headSeq":1,"feedHash":"{FEED_ONE}"}}"#),
    )]);
    let recovery = sevra()
        .args(["pull", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &recovery_base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(recovery.status.success(), "{}", all_output(&recovery));
    assert!(
        all_output(&recovery).contains("recovered an interrupted pull"),
        "{}",
        all_output(&recovery)
    );
    recovery_handle.join().unwrap();
    assert_eq!(
        recovery_log.lock().unwrap().len(),
        1,
        "recovery completes before the first head request"
    );
    assert_eq!(std::fs::read(brain.join("a.md")).unwrap(), b"alpha");
    for index in 0..128 {
        assert!(
            !brain.join(format!("records/{index:04}.md")).exists(),
            "partially installed path survived recovery"
        );
    }
    assert!(
        !brain.join("records").exists(),
        "recovery removes transaction-created empty directories"
    );
    assert!(!brain.join(".sevra-pull-journal.json").exists());
    assert!(
        std::fs::read_dir(&brain).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".sevra-pull-backup-")
        }),
        "recovery removed its private backup directory"
    );
}

#[test]
fn cloned_push_sends_the_baseline_and_force_is_the_explicit_bypass() {
    for force in [false, true] {
        let work = tempfile::tempdir().unwrap();
        let final_response = if force {
            format!(
                r#"{{"brain":"brain-1","slug":"b","headSeq":2,"feedHash":"{FEED_TWO}","packSha256":"{}","indexed":{{"documents":1,"assets":0}}}}"#,
                "a".repeat(64)
            )
        } else {
            r#"{"error":"This brain advanced from baseline sequence 1 to 2. Pull before pushing.","code":"stale_baseline","expectedHeadSeq":1,"currentHeadSeq":2}"#.to_string()
        };
        let (base, log, handle) = mock_hub(vec![
            (200, clone_snapshot(1, FEED_ONE, "alpha")),
            (200, r#"{"id":"brain-1"}"#.to_string()),
            (if force { 200 } else { 409 }, final_response),
        ]);
        sevra()
            .args(["clone", "b", "brain"])
            .current_dir(work.path())
            .env("SEVRA_HUB_URL", &base)
            .env("SEVRA_API_KEY", "x")
            .assert()
            .success();
        std::fs::write(work.path().join("brain/a.md"), "local beta").unwrap();
        let mut command = sevra();
        command.args(["push", "brain", "--brain", "b", "--skip-assets"]);
        if force {
            command.arg("--force");
        }
        let push = command
            .current_dir(work.path())
            .env("SEVRA_HUB_URL", &base)
            .env("SEVRA_API_KEY", "x")
            .output()
            .unwrap();
        assert_eq!(push.status.success(), force, "{}", all_output(&push));
        if !force {
            assert!(all_output(&push).contains("Pull before pushing"));
        }
        handle.join().unwrap();
        let requests = log.lock().unwrap();
        let body: serde_json::Value = serde_json::from_str(&requests[2].body).unwrap();
        if force {
            assert!(body.get("expected_head_seq").is_none());
            assert_eq!(body["allow_shrink"], true);
        } else {
            assert_eq!(body["expected_head_seq"], 1);
        }
    }
}

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

fn manifest_asset_store(path: &str, bytes: &[u8], scope: Option<&str>) -> tempfile::TempDir {
    let t = store_dir(&[(
        "a.md",
        "---\ntype: note\nsummary: asset fixture\n---\nasset fixture\n",
    )]);
    let asset = t.path().join(path);
    std::fs::create_dir_all(asset.parent().unwrap()).unwrap();
    std::fs::write(&asset, bytes).unwrap();
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    std::fs::write(
        t.path().join("assets.jsonl"),
        format!(
            "{{\"path\":\"{path}\",\"sha256\":\"{sha256}\",\"bytes\":{}}}\n",
            bytes.len()
        ),
    )
    .unwrap();
    if let Some(scope) = scope {
        std::fs::write(t.path().join(".sevralocal"), scope).unwrap();
    }
    t
}

#[test]
fn push_refuses_a_secret_in_manifest_bound_asset_bytes_before_any_request() {
    let token = format!("AKIA{}", "S".repeat(16));
    let body = format!("provider_key={token}\n");
    let t = manifest_asset_store("_files/provider.env", body.as_bytes(), None);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", "http://localhost:9")
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = all_output(&out);
    assert!(
        all.contains("_files/provider.env") && all.contains("AWS access key id"),
        "asset hit is reported in the standard refusal shape: {all}"
    );
    assert!(!all.contains(&token), "asset credential leaked: {all}");
    assert!(
        !all.contains("hub unreachable"),
        "the asset gate must run before the first request: {all}"
    );
    assert!(
        all.contains("Already-pushed bytes persist")
            && all.contains("Current-state withdrawal")
            && all.contains("historical purge")
            && all.contains("incident policy")
            && !all.contains("Rotate at the issuer immediately"),
        "the refusal carries precise existing-data remediation: {all}"
    );
}

#[test]
fn asset_scan_ignores_a_token_shape_inside_a_longer_minified_run() {
    let token = format!("ghp_{}", "m".repeat(36));
    let minified = format!("const x=\"A{token}Z\";");
    let t = manifest_asset_store("_files/bundle.min.js", minified.as_bytes(), None);
    sevra()
        .args(["secrets", "scan", t.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("no matches"));
}

#[test]
fn asset_scan_names_bounded_binary_and_large_coverage_gaps() {
    let t = manifest_asset_store("_files/image.bin", &[0xff, 0xfe, 0xfd], None);
    let huge_path = t.path().join("_files/huge.txt");
    let huge = std::fs::File::create(&huge_path).unwrap();
    huge.set_len(8 * 1024 * 1024 + 1).unwrap();
    drop(huge);
    let mut manifest = std::fs::read_to_string(t.path().join("assets.jsonl")).unwrap();
    manifest.push_str(&format!(
        "{{\"path\":\"_files/huge.txt\",\"sha256\":\"{}\",\"bytes\":{}}}\n",
        "0".repeat(64),
        8 * 1024 * 1024 + 1
    ));
    std::fs::write(t.path().join("assets.jsonl"), manifest).unwrap();

    sevra()
        .args(["secrets", "scan", t.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("no matches"))
        .stderr(
            predicate::str::contains("1 over 8 MiB")
                .and(predicate::str::contains("1 binary/non-UTF-8")),
        );

    let json = sevra()
        .args(["secrets", "scan", t.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(json.status.success(), "{}", all_output(&json));
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let scan = &value["assetSecretScan"];
    assert_eq!(scan["skipped"]["tooLarge"], 1);
    assert_eq!(scan["skipped"]["nonUtf8"], 1);
    assert_eq!(scan["maxInspectedBytes"], 8 * 1024 * 1024);
    assert_eq!(scan["maxTotalInspectedBytes"], 64 * 1024 * 1024);
}

#[test]
fn kept_home_asset_is_neither_scanned_nor_uploaded_but_quarantine_can_see_it() {
    let token = format!("xoxb-{}", "7".repeat(10));
    let body = format!("SLACK_TOKEN={token}\n");
    let path = "_files/private.env";
    let t = manifest_asset_store(path, body.as_bytes(), Some("_files/private.env\n"));
    let manifest = std::fs::read_to_string(t.path().join("assets.jsonl")).unwrap();
    let sha = serde_json::from_str::<serde_json::Value>(manifest.trim()).unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let missing = format!(
        r#"{{"assets":[{{"path":"{path}","sha256":"{sha}","bytes":{},"required":true,"presentInR2":false}}],"truncated":false}}"#,
        body.len()
    );
    let (base, log, handle) = mock_hub(vec![(200, push_response(1, 1, 1)), (200, missing)]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "push failed: {}", all_output(&out));
    let all = all_output(&out);
    assert!(!all.contains(&token), "kept-home bytes leaked: {all}");
    assert!(all.contains("assets: 1 kept home"), "{all}");
    handle.join().unwrap();
    assert_eq!(
        log.lock().unwrap().len(),
        2,
        "push + missing inventory only; no presign or PUT"
    );

    let quarantine = sevra()
        .args(["secrets", "quarantine", t.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(quarantine.status.success(), "{}", all_output(&quarantine));
    let all = all_output(&quarantine);
    assert!(
        all.contains("1 hit file(s) already covered by .sevralocal"),
        "full-view quarantine sees the kept asset: {all}"
    );
    assert!(!all.contains(&token), "quarantine leaked the value: {all}");
    assert_eq!(
        std::fs::read_to_string(t.path().join(".sevralocal")).unwrap(),
        "_files/private.env\n"
    );
}

#[test]
fn push_syncs_missing_assets_after_commit() {
    let t = asset_store();
    let missing = format!(
        r#"{{"assets":[{{"path":"_files/x.bin","sha256":"{BLOB_SHA}","bytes":4,"required":true,"presentInR2":false}}],"truncated":false}}"#
    );
    let presigned = format!(
        r#"{{"items":[{{"sha256":"{BLOB_SHA}","url":"{{BASE}}/blob-put","method":"PUT","reservationId":"01hzy3v7q8r9s0t1v2w3x4y5z7","headers":{{"content-length":"4"}}}}]}}"#
    );
    let (base, log, handle) = mock_hub(vec![
        (200, push_response(1, 1, 1)),
        (200, missing),
        (200, presigned),
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
    assert_eq!(
        reqs.len(),
        5,
        "push, list, transfer, PUT, confirm: {reqs:?}"
    );
    assert_eq!(reqs[1].path, "/api/hub/brains/b/assets?status=missing");
    assert_eq!(reqs[2].path, "/api/hub/brains/b/assets/transfer");
    assert_eq!(reqs[3].method, "PUT");
    assert_eq!(reqs[3].path, "/blob-put");
    assert_eq!(reqs[3].body, "BLOB", "the exact blob bytes ride the PUT");
    assert_eq!(reqs[4].path, "/api/hub/brains/b/assets/transfer/confirm");
    assert!(
        reqs[4].body.contains(BLOB_SHA) && reqs[4].body.contains("01hzy3v7q8r9s0t1v2w3x4y5z7"),
        "confirm carries hash + reservation: {}",
        reqs[4].body
    );
}

#[test]
fn push_batches_multiple_assets_into_one_planning_and_confirm_window() {
    let t = tempfile::tempdir().unwrap();
    let blobs = [
        ("_files/one.bin", b"ONE".as_slice()),
        ("_files/two.bin", b"TWO".as_slice()),
        ("_files/three.bin", b"THREE".as_slice()),
    ];
    let mut manifest = String::new();
    let mut missing_rows = Vec::new();
    let mut transfer_items = Vec::new();
    for (index, (path, bytes)) in blobs.iter().enumerate() {
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let destination = t.path().join(path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(destination, bytes).unwrap();
        manifest.push_str(
            &serde_json::json!({ "path": path, "sha256": sha256, "bytes": bytes.len() })
                .to_string(),
        );
        manifest.push('\n');
        missing_rows.push(serde_json::json!({
            "path": path,
            "sha256": sha256,
            "bytes": bytes.len(),
            "required": true,
            "presentInR2": false,
        }));
        transfer_items.push(serde_json::json!({
            "sha256": sha256,
            "url": format!("{{BASE}}/blob-put-{index}"),
            "method": "PUT",
            "reservationId": format!("01hzy3v7q8r9s0t1v2w3x4y5{}", index + 1),
            "headers": { "content-length": bytes.len().to_string() },
        }));
    }
    std::fs::write(
        t.path().join("a.md"),
        "---\ntype: note\nsummary: batch fixture\n---\nbatch fixture\n",
    )
    .unwrap();
    std::fs::write(t.path().join("assets.jsonl"), manifest).unwrap();
    let (base, log, handle) = mock_hub(vec![
        (200, push_response(1, 3, 1)),
        (
            200,
            serde_json::json!({ "assets": missing_rows, "truncated": false }).to_string(),
        ),
        (
            200,
            serde_json::json!({ "items": transfer_items }).to_string(),
        ),
        (200, "{}".to_string()),
        (200, "{}".to_string()),
        (200, "{}".to_string()),
        (200, r#"{"present":true,"confirmed":3}"#.to_string()),
    ]);

    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b", "--json"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", all_output(&out));
    let output: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(output["assetSync"]["uploaded"], 3);
    assert_eq!(output["assetSync"]["windows"], 1);
    assert_eq!(output["assetSync"]["hubRequests"], 3);

    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == "/api/hub/brains/b/assets/transfer")
            .count(),
        1,
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        3,
    );
    let confirm = requests
        .iter()
        .find(|request| request.path == "/api/hub/brains/b/assets/transfer/confirm")
        .unwrap();
    let confirm_body: serde_json::Value = serde_json::from_str(&confirm.body).unwrap();
    assert_eq!(confirm_body["items"].as_array().unwrap().len(), 3);
}

#[test]
fn push_skip_assets_makes_no_asset_requests() {
    let t = asset_store();
    let (base, log, handle) = mock_hub(vec![(200, push_response(1, 1, 1))]);
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
fn push_refuses_sparse_oversize_asset_before_read_or_presign() {
    let t = asset_store();
    let sparse = std::fs::OpenOptions::new()
        .write(true)
        .open(t.path().join("_files/x.bin"))
        .unwrap();
    sparse.set_len(2 * 1024 * 1024 * 1024 + 1).unwrap();
    drop(sparse);
    let missing = format!(
        r#"{{"assets":[{{"path":"_files/x.bin","sha256":"{BLOB_SHA}","bytes":4,"required":true,"presentInR2":false}}],"truncated":false}}"#
    );
    let (base, log, handle) = mock_hub(vec![(200, push_response(1, 1, 1)), (200, missing)]);
    let out = sevra()
        .args(["push", t.path().to_str().unwrap(), "--brain", "b"])
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(out.status.success(), "push failed: {}", all_output(&out));
    assert!(
        all_output(&out).contains("local file exceeds the 2 GiB client asset limit"),
        "{}",
        all_output(&out)
    );
    handle.join().unwrap();
    assert_eq!(
        log.lock().unwrap().len(),
        2,
        "oversize metadata is rejected before presign or body read"
    );
}

#[test]
fn export_restores_missing_assets_sha_verified() {
    let manifest_line =
        "{\\\"path\\\":\\\"_files/x.bin\\\",\\\"sha256\\\":\\\"671a0d168d8e3d31819402ac7c3a3cc0abedebbf6a4cda26deacd89724bd6bdc\\\",\\\"bytes\\\":4}\\n";
    let export_body = format!(
        r#"{{"slug":"b","files":[{{"path":"a.md","content":"alpha"}},{{"path":"assets.jsonl","content":"{manifest_line}"}}]}}"#
    );
    let presigned = format!(
        r#"{{"items":[{{"sha256":"{BLOB_SHA}","url":"{{BASE}}/blob-get","method":"GET"}}]}}"#
    );
    let (base, log, handle) = mock_hub(vec![
        (200, export_body),
        (200, presigned),
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
    assert_eq!(reqs.len(), 3, "export, transfer, GET: {reqs:?}");
    assert_eq!(reqs[1].path, "/api/hub/brains/b/assets/transfer");
    let restored = std::fs::read(work.path().join("out/_files/x.bin")).unwrap();
    assert_eq!(restored, b"BLOB", "restored bytes match the manifest hash");
}

#[cfg(unix)]
#[test]
fn export_rebuilds_dbmd_catalogs_before_atomic_publish() {
    let export_body = serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "vaultItems": [],
        "files": [
            {
                "path": "DB.md",
                "content": "---\ntype: db-md\nname: Test\nowner: Test\nscope: test\nsummary: Test store.\n---\n# Test\n"
            },
            {
                "path": "records/notes/fact.md",
                "content": "---\ntype: note\nsummary: Test fact.\n---\n# Fact\n"
            }
        ]
    })
    .to_string();
    let (base, _log, handle) = mock_hub(vec![(200, export_body)]);
    let work = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    fake_v2_dbmd(
        bin.path(),
        "#!/bin/sh\n[ \"$1 $2 $3\" = \"index rebuild --json\" ] || exit 64\nmkdir -p records/notes\nprintf '%s\\n' '{\"path\":\"records/notes/fact.md\"}' > records/notes/index.jsonl\n",
    );
    let out = sevra()
        .args(["export", "b", "out", "--json"])
        .current_dir(work.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()))
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(out.status.success(), "export failed: {}", all_output(&out));
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["catalogsRebuilt"], true);
    assert_eq!(
        std::fs::read_to_string(work.path().join("out/records/notes/index.jsonl")).unwrap(),
        "{\"path\":\"records/notes/fact.md\"}\n"
    );
    handle.join().unwrap();
}

#[test]
fn export_always_writes_a_private_vault_name_manifest_without_values() {
    let export_body = r#"{
        "brain":"brain-id",
        "slug":"b",
        "vaultItems":["Z_TOKEN","API_KEY"],
        "files":[{"path":"DB.md","content":"---\ntype: db-md\nscope: test\n---\n"},{"path":"records/a.md","content":"alpha"}]
    }"#;
    let (base, log, handle) = mock_hub(vec![(200, export_body.to_string())]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out", "--json"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(out.status.success(), "export failed: {}", all_output(&out));
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["vaultFile"], ".sevra-vault.json");
    assert_eq!(
        result["vaultNames"],
        serde_json::json!(["API_KEY", "Z_TOKEN"])
    );
    assert_eq!(result["vaultValuesIncluded"], false);

    let path = work.path().join("out/.sevra-vault.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["brain"], "brain-id");
    assert_eq!(manifest["names"], serde_json::json!(["API_KEY", "Z_TOKEN"]));
    assert!(manifest.get("valuesBase64").is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1, "default export needs no value reads");
    assert_eq!(
        reqs[0].path,
        "/api/hub/brains/b/export?format=pack&includeVaultNames=1"
    );
}

#[test]
fn export_recovers_from_the_hardened_hub_by_pinning_the_verified_feed_head() {
    let export_body = serde_json::json!({
        "brain": "brain-1",
        "slug": "b",
        "headSeq": 1,
        "feedHash": FEED_ONE,
        "vaultItems": [],
        "files": [{"path": "DB.md", "content": "---\ntype: db-md\nscope: test\n---\n"}],
    })
    .to_string();
    let (base, log, handle) = mock_hub(vec![
        (
            400,
            r#"{"error":"format=pack requires canonical atSeq and feedHash parameters from the verified feed.","code":"snapshot_address_required"}"#.to_string(),
        ),
        (
            200,
            format!(r#"{{"id":"brain-1","slug":"b","headSeq":1,"feedHash":"{FEED_ONE}"}}"#),
        ),
        (200, export_body),
    ]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out", "--json"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(out.status.success(), "export failed: {}", all_output(&out));
    assert!(work.path().join("out/DB.md").is_file());

    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].path,
        "/api/hub/brains/b/export?format=pack&includeVaultNames=1"
    );
    assert_eq!(requests[1].path, "/api/hub/brains/b");
    assert_eq!(
        requests[2].path,
        format!(
            "/api/hub/brains/b/export?format=pack&atSeq=1&feedHash={FEED_ONE}&includeVaultNames=1"
        )
    );
}

#[test]
fn clone_recovers_from_the_hardened_hub_by_pinning_the_verified_feed_head() {
    let (base, log, handle) = mock_hub(vec![
        (
            400,
            r#"{"error":"format=pack requires canonical atSeq and feedHash parameters from the verified feed.","code":"snapshot_address_required"}"#.to_string(),
        ),
        (
            200,
            format!(r#"{{"id":"brain-1","slug":"b","headSeq":1,"feedHash":"{FEED_ONE}"}}"#),
        ),
        (200, clone_snapshot(1, FEED_ONE, "alpha")),
    ]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["clone", "b", "brain"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(out.status.success(), "clone failed: {}", all_output(&out));
    assert_eq!(
        std::fs::read(work.path().join("brain/a.md")).unwrap(),
        b"alpha"
    );

    handle.join().unwrap();
    let requests = log.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].path, "/api/hub/brains/b/export?format=pack");
    assert_eq!(requests[1].path, "/api/hub/brains/b");
    assert_eq!(
        requests[2].path,
        format!("/api/hub/brains/b/export?format=pack&atSeq=1&feedHash={FEED_ONE}")
    );
}

#[test]
fn export_with_secrets_reads_each_value_and_warns_without_echoing_it() {
    let export_body = r#"{
        "brain":"brain-id",
        "slug":"b",
        "vaultItems":["BINARY_KEY","API_KEY"],
        "files":[{"path":"DB.md","content":"---\ntype: db-md\nscope: test\n---\n"}]
    }"#;
    let (base, log, handle) = mock_hub(vec![
        (200, export_body.to_string()),
        (
            200,
            r#"{"name":"API_KEY","valueBase64":"dmF1bHQtVE9QU0VDUkVULXZhbHVl","encoding":"base64"}"#
                .to_string(),
        ),
        (
            200,
            r#"{"name":"BINARY_KEY","valueBase64":"AAEC/w==","encoding":"base64"}"#
                .to_string(),
        ),
    ]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out", "--with-secrets"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(out.status.success(), "export failed: {}", all_output(&out));
    let shown = all_output(&out);
    assert!(shown.contains("as sensitive as the credentials themselves"));
    assert!(shown.contains("values included"));
    assert!(
        !shown.contains("TOPSECRET"),
        "value leaked into output: {shown}"
    );
    assert!(
        !shown.contains("dmF1bHQt"),
        "base64 leaked into output: {shown}"
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.path().join("out/.sevra-vault.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["names"],
        serde_json::json!(["API_KEY", "BINARY_KEY"])
    );
    assert_eq!(
        manifest["valuesBase64"]["API_KEY"],
        "dmF1bHQtVE9QU0VDUkVULXZhbHVl"
    );
    assert_eq!(manifest["valuesBase64"]["BINARY_KEY"], "AAEC/w==");

    handle.join().unwrap();
    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 3);
    assert_eq!(
        reqs[1].path,
        "/api/hub/brains/b/vault?name=API_KEY&purpose=export"
    );
    assert_eq!(
        reqs[2].path,
        "/api/hub/brains/b/vault?name=BINARY_KEY&purpose=export"
    );
    let expected_auth = format!("Bearer {MOCK_KEY}");
    assert!(reqs
        .iter()
        .all(|request| request.authorization.as_deref() == Some(expected_auth.as_str())));
}

#[test]
fn export_with_secrets_fails_closed_before_publish_on_a_bad_value() {
    let export_body = r#"{
        "brain":"brain-id",
        "slug":"b",
        "vaultItems":["API_KEY"],
        "files":[{"path":"DB.md","content":"---\ntype: db-md\nscope: test\n---\n"}]
    }"#;
    let (base, _log, handle) = mock_hub(vec![
        (200, export_body.to_string()),
        (
            200,
            r#"{"name":"API_KEY","valueBase64":"vault-TOPSECRET-not-base64"}"#.to_string(),
        ),
    ]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out", "--with-secrets"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", MOCK_KEY)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let shown = all_output(&out);
    assert!(shown.contains("invalid vault value"), "{shown}");
    assert!(!shown.contains("TOPSECRET"), "bad value leaked: {shown}");
    assert!(!work.path().join("out").exists());
    handle.join().unwrap();
}

#[test]
fn export_refuses_huge_manifest_asset_before_presign() {
    let manifest_line = format!(
        "{{\\\"path\\\":\\\"_files/x.bin\\\",\\\"sha256\\\":\\\"{BLOB_SHA}\\\",\\\"bytes\\\":2147483649}}\\n"
    );
    let export_body = format!(
        r#"{{"slug":"b","files":[{{"path":"a.md","content":"alpha"}},{{"path":"assets.jsonl","content":"{manifest_line}"}}]}}"#
    );
    let (base, log, handle) = mock_hub(vec![(200, export_body)]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert!(
        all_output(&out).contains("exceeds the 2 GiB client asset limit"),
        "{}",
        all_output(&out)
    );
    assert!(!work.path().join("out/_files/x.bin").exists());
    handle.join().unwrap();
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "huge declaration is rejected before a presign request"
    );
}

#[test]
fn export_rejects_unicode_aliases_before_creating_the_root() {
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"slug":"b","files":[{"path":"é.md","content":"NFC"},{"path":"é.md","content":"NFD"}]}"#
            .to_string(),
    )]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out", "--skip-assets"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert!(all_output(&out).contains("alias collision"));
    assert!(!work.path().join("out").exists());
    handle.join().unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn export_rejects_a_single_noncanonical_core_control_before_mutation() {
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"slug":"b","files":[{"path":"Assets.jsonl","content":"ATTACK"}]}"#.to_string(),
    )]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out", "--skip-assets"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert!(
        all_output(&out).contains("non-canonical assets.jsonl"),
        "{}",
        all_output(&out)
    );
    assert!(!work.path().join("out").exists());
    handle.join().unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn export_rejects_hidden_components_before_root_or_presign() {
    for path in [".git/config", "records/.ssh/key", ".sevralocal/owned.md"] {
        let export_body =
            format!(r#"{{"slug":"b","files":[{{"path":"{path}","content":"ATTACK"}}]}}"#);
        let (base, log, handle) = mock_hub(vec![(200, export_body)]);
        let work = tempfile::tempdir().unwrap();
        let out = sevra()
            .args(["export", "b", "out"])
            .current_dir(work.path())
            .env("SEVRA_HUB_URL", &base)
            .env("SEVRA_API_KEY", "x")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{}", all_output(&out));
        assert!(all_output(&out).contains("hidden control component"));
        assert!(!work.path().join("out").exists());
        handle.join().unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
    }
}

#[test]
fn export_rejects_existing_case_and_unicode_aliases_without_replacement() {
    for (remote, existing) in [("assets.jsonl", "Assets.jsonl"), ("é.md", "é.md")] {
        let content = if remote == "assets.jsonl" {
            ""
        } else {
            "ATTACK"
        };
        let export_body =
            format!(r#"{{"slug":"b","files":[{{"path":"{remote}","content":"{content}"}}]}}"#);
        let (base, log, handle) = mock_hub(vec![(200, export_body)]);
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir(work.path().join("out")).unwrap();
        std::fs::write(work.path().join("out").join(existing), b"SAFE").unwrap();
        let out = sevra()
            .args(["export", "b", "out", "--skip-assets"])
            .current_dir(work.path())
            .env("SEVRA_HUB_URL", &base)
            .env("SEVRA_API_KEY", "x")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{}", all_output(&out));
        assert!(
            all_output(&out).contains("destination already exists"),
            "{}",
            all_output(&out)
        );
        assert_eq!(
            std::fs::read(work.path().join("out").join(existing)).unwrap(),
            b"SAFE"
        );
        handle.join().unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
    }
}

#[test]
fn export_rejects_asset_store_alias_before_presign_or_mutation() {
    let manifest_line = format!(
        "{{\\\"path\\\":\\\"Assets.jsonl\\\",\\\"sha256\\\":\\\"{BLOB_SHA}\\\",\\\"bytes\\\":4}}\\n"
    );
    let export_body = format!(
        r#"{{"slug":"b","files":[{{"path":"a.md","content":"alpha"}},{{"path":"assets.jsonl","content":"{manifest_line}"}}]}}"#
    );
    let (base, log, handle) = mock_hub(vec![(200, export_body)]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert!(all_output(&out).contains("reserved asset path"));
    assert!(!work.path().join("out").exists());
    handle.join().unwrap();
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "portable manifest refusal happens before presign"
    );
}

#[test]
fn export_stream_refuses_first_byte_past_declared_length_without_installing() {
    let manifest_line =
        "{\\\"path\\\":\\\"_files/x.bin\\\",\\\"sha256\\\":\\\"671a0d168d8e3d31819402ac7c3a3cc0abedebbf6a4cda26deacd89724bd6bdc\\\",\\\"bytes\\\":4}\\n";
    let export_body = format!(
        r#"{{"slug":"b","files":[{{"path":"a.md","content":"alpha"}},{{"path":"assets.jsonl","content":"{manifest_line}"}}]}}"#
    );
    let presigned = format!(
        r#"{{"items":[{{"sha256":"{BLOB_SHA}","url":"{{BASE}}/blob-get","method":"GET"}}]}}"#
    );
    let (base, log, handle) = mock_hub(vec![
        (200, export_body),
        (200, presigned),
        (200, "BLOBS".to_string()),
    ]);
    let work = tempfile::tempdir().unwrap();
    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert!(
        all_output(&out).contains("presigned download exceeded the supported size"),
        "{}",
        all_output(&out)
    );
    assert!(
        !work.path().join("out/_files/x.bin").exists(),
        "an oversize stream must never be installed"
    );
    handle.join().unwrap();
    assert_eq!(log.lock().unwrap().len(), 3);
}

#[cfg(unix)]
#[test]
fn export_refuses_a_symlinked_root_without_touching_its_target() {
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"slug":"b","files":[{"path":"victim","content":"ATTACK"}]}"#.to_string(),
    )]);
    let work = tempfile::tempdir().unwrap();
    let outside = work.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("victim"), b"SAFE").unwrap();
    std::os::unix::fs::symlink(&outside, work.path().join("out")).unwrap();

    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"SAFE");
    assert!(
        all_output(&out).contains("without following links"),
        "{}",
        all_output(&out)
    );
    handle.join().unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn export_prefix_collision_is_rejected_before_replacing_an_existing_file() {
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"slug":"b","files":[{"path":"a","content":"NEW"},{"path":"a/b","content":"COLLISION"}]}"#
            .to_string(),
    )]);
    let work = tempfile::tempdir().unwrap();
    std::fs::create_dir(work.path().join("out")).unwrap();
    std::fs::write(work.path().join("out/a"), b"OLD").unwrap();

    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert!(
        all_output(&out).contains("prefix collision"),
        "{}",
        all_output(&out)
    );
    assert_eq!(std::fs::read(work.path().join("out/a")).unwrap(), b"OLD");
    handle.join().unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn export_refuses_a_core_file_leaf_symlink_without_touching_its_target() {
    let (base, log, handle) = mock_hub(vec![(
        200,
        r#"{"slug":"b","files":[{"path":"victim","content":"ATTACK"}]}"#.to_string(),
    )]);
    let work = tempfile::tempdir().unwrap();
    let outside = work.path().join("outside");
    std::fs::write(&outside, b"SAFE").unwrap();
    std::fs::create_dir(work.path().join("out")).unwrap();
    std::os::unix::fs::symlink(&outside, work.path().join("out/victim")).unwrap();

    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert_eq!(std::fs::read(&outside).unwrap(), b"SAFE");
    assert!(
        all_output(&out).contains("destination leaf is a symlink"),
        "{}",
        all_output(&out)
    );
    handle.join().unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn export_asset_restore_refuses_a_planted_leaf_symlink() {
    let manifest_line =
        "{\\\"path\\\":\\\"_files/x.bin\\\",\\\"sha256\\\":\\\"671a0d168d8e3d31819402ac7c3a3cc0abedebbf6a4cda26deacd89724bd6bdc\\\",\\\"bytes\\\":4}\\n";
    let export_body = format!(
        r#"{{"slug":"b","files":[{{"path":"a.md","content":"alpha"}},{{"path":"assets.jsonl","content":"{manifest_line}"}}]}}"#
    );
    // A hardened client refuses before asking for a presigned asset URL, so
    // the mock needs only the export answer.
    let (base, log, handle) = mock_hub(vec![(200, export_body)]);
    let work = tempfile::tempdir().unwrap();
    let victim = work.path().join("victim");
    std::fs::write(&victim, b"SAFE").unwrap();
    std::fs::create_dir_all(work.path().join("out/_files")).unwrap();
    std::os::unix::fs::symlink(&victim, work.path().join("out/_files/x.bin")).unwrap();

    let out = sevra()
        .args(["export", "b", "out"])
        .current_dir(work.path())
        .env("SEVRA_HUB_URL", &base)
        .env("SEVRA_API_KEY", "x")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", all_output(&out));
    assert_eq!(std::fs::read(&victim).unwrap(), b"SAFE");
    assert!(
        all_output(&out).contains("destination leaf is a symlink"),
        "{}",
        all_output(&out)
    );
    handle.join().unwrap();
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "no asset presign/download after filesystem refusal"
    );
}

#[cfg(unix)]
#[test]
fn export_asset_restore_refuses_an_ancestor_swapped_during_presign() {
    for (remote, planted) in [("é.md", "é.md"), ("A.md", "a.md")] {
        let manifest_line =
            "{\\\"path\\\":\\\"_files/x.bin\\\",\\\"sha256\\\":\\\"671a0d168d8e3d31819402ac7c3a3cc0abedebbf6a4cda26deacd89724bd6bdc\\\",\\\"bytes\\\":4}\\n";
        let export_body = format!(
            r#"{{"slug":"b","files":[{{"path":"{remote}","content":"REMOTE"}},{{"path":"assets.jsonl","content":"{manifest_line}"}}]}}"#
        );
        let work = tempfile::tempdir().unwrap();
        let export_root = work.path().join("out");
        let planted_path = export_root.join(planted);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let base_for_server = base.clone();
        let handle = std::thread::spawn(move || {
            for turn in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_mock_request(&mut stream).unwrap();
                match turn {
                    0 => respond_json(&mut stream, 200, &export_body),
                    1 => {
                        assert!(request.path.contains("/assets/transfer"));
                        std::fs::create_dir(&export_root).unwrap();
                        std::fs::write(&planted_path, b"SAFE").unwrap();
                        respond_json(
                            &mut stream,
                            200,
                            &format!(
                                r#"{{"items":[{{"sha256":"{BLOB_SHA}","url":"{base_for_server}/blob","method":"GET"}}]}}"#
                            ),
                        );
                    }
                    2 => respond_json(&mut stream, 200, "BLOB"),
                    _ => unreachable!(),
                }
            }
        });
        let out = sevra()
            .args(["export", "b", "out"])
            .current_dir(work.path())
            .env("SEVRA_HUB_URL", &base)
            .env("SEVRA_API_KEY", "x")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{}", all_output(&out));
        assert!(
            all_output(&out).contains("appeared before atomic publish"),
            "{}",
            all_output(&out)
        );
        assert_eq!(
            std::fs::read(work.path().join("out").join(planted)).unwrap(),
            b"SAFE"
        );
        assert!(!work.path().join("out/_files/x.bin").exists());
        handle.join().unwrap();
    }
}
