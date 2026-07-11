//! Offline behavior tests (assert_cmd) — the invariants that must hold with no
//! network: version shape, help, flag parsing, the not-logged-in path, the
//! HTTPS guard, and the --json error contract. The live hub parity proof is
//! the platform repo's hub-demo battery driven with SEVRA_BIN.

use assert_cmd::Command;
use predicates::prelude::*;

fn sevra() -> Command {
    let mut c = Command::cargo_bin("sevra").unwrap();
    // Isolate HOME so no real ~/.sevra credential leaks in.
    c.env(
        "HOME",
        std::env::temp_dir().join(format!("sevra-test-{}", std::process::id())),
    );
    c.env_remove("SEVRA_API_KEY");
    c.env_remove("SEVRA_HUB_URL");
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
            .env("SEVRA_API_KEY", "vc_account_TOPSECRET\nLEAKCHECK")
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
        .env("SEVRA_API_KEY", " vc_account_x \n")
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
