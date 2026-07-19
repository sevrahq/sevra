# Changelog

## Unreleased

- New: **`sevra mcp` — a stdio MCP server over the hub's read surface.** Point
  any MCP client (Claude Code, Claude Desktop) at
  `{"command": "sevra", "args": ["mcp"]}`: four read-only tools (list_brains,
  search_brain, get_record, graph) against your hosted brains, using the
  stored sign-in (`SEVRA_API_KEY` / `SEVRA_HUB_URL` override it). stdout
  carries only JSON-RPC frames; diagnostics go to stderr. Without a
  credential it reaches public brains only. For agents that cannot run a CLI;
  the CLI stays the primary, recommended surface.

## 0.2.2 — 2026-07-18

- **Self-update now checks the origin's digest as well as the signature.** The
  publisher key was the only root of trust on a path that runs unattended; the
  hub serves the expected digest from a separately deployed manifest, so a
  key compromise alone is no longer enough. A missing or unreachable digest
  does not block the update (the signature still gates it); a digest that
  disagrees stops it.
- Fixed: signing in again left the previous session live on your account
  forever. Overwriting the stored credential dropped its id, so nothing could
  revoke it and it quietly consumed one of the ten credential slots on every
  repeat login. The displaced session is now revoked first.
- Hardened: the config temp file is created exclusively (`create_new`) so a
  pre-planted symlink at the predictable temp path cannot capture a session
  key, and `~/.sevra` is tightened to 0700.

## 0.2.1 — 2026-07-18

Security and robustness fixes from a full review of the 0.2.0 sign-in work.
**0.2.1 is required to sign in through the browser**: the hub now demands the
one-time authorization code described below, which 0.2.0 does not send.

- **Security: browser sign-in now requires an authorization code delivered
  through the loopback redirect**, alongside the PKCE verifier. 0.2.0 relied on
  the verifier alone, which proves only that you STARTED a sign-in — so someone
  could start one, get a signed-in person to approve the link, and redeem it
  themselves. Approving a link you did not start now hands the other party
  nothing.
- **Security: the browser URL is built locally** from the configured hub rather
  than taken from the hub's response, so hub-supplied text can never reach the
  platform opener (on Windows, `cmd`'s parser).
- Fixed: a hub-supplied poll interval above 30 seconds panicked the process.
- Fixed: a connection that opened but sent nothing (browsers preconnect to
  loopback) could hang sign-in forever; connections now time out, and only a
  callback carrying the code completes the flow.
- Fixed: a split TCP read could drop the callback and silently strand sign-in.
- Fixed: `logout` could exit before removing the local credential when the
  stored hub or key was malformed, and it now says so when it cannot confirm
  the server-side revoke instead of always reporting success.
- Fixed: throttling and transient hub errors during the browser exchange are
  retried with backoff instead of ending the sign-in.
- Fixed: the installers treated any `openssl` as an Ed25519 verifier. Stock
  macOS ships LibreSSL, which cannot verify it, so a good download was reported
  as a failed publisher signature and the install aborted. They now probe for
  capability and fall back to the manifest digest when the tool cannot verify.

## 0.2.0 — 2026-07-18

- New: **`sevra login` signs in through your browser** — no key to paste. It
  binds a loopback port, opens the browser, and collects a session when the
  approved sign-in is handed back to that port. The session is never delivered
  through the browser URL: completing a sign-in requires both the PKCE
  verifier (held only by the process that started it) and a one-time
  authorization code that reaches that process solely through the loopback
  redirect. Approving a link you did not start therefore hands nothing to
  whoever sent it. As with any consent screen, only approve a sign-in you just
  initiated yourself.
- New: **sign-in code fallback** for headless/SSH or approving from another
  computer — `sevra login` prints a short code and a URL, chosen automatically
  when no browser can open, or forced with `--no-browser`.
- New: **server-managed sessions.** A browser/code sign-in mints a session
  that expires after 90 days of inactivity (slid forward on use), listed and
  revocable in the dashboard. `sevra logout` revokes it server-side. A stored
  `--key` is still supported for scripts and CI and is left untouched by
  logout.
- Reliability: the sign-in poll tolerates a transport blip mid-wait instead of
  aborting, and clamps hub-supplied timing values.

## 0.1.6 — 2026-07-14

- Reliability: hub requests and presigned pack transfers retry bounded DNS,
  connection, and proxy-connect failures that occur before any request can
  reach the server. Mid-stream I/O is never replayed, so mutating commands do
  not guess after bytes may have crossed the wire.
- Tests: a delayed loopback server locks the connect-retry regression.

## 0.1.5 — 2026-07-14

- New: **native Windows (x64)** — the release chain builds, signs, and ships
  `sevra-windows-x86_64.exe` (MSVC target); Windows-on-ARM runs it under the
  built-in x64 emulation. Self-update swaps the running exe Windows-style:
  the old binary is parked aside as `sevra.exe.old.<pid>` (a rename ONTO a
  running exe is refused by the OS), the new one renamed in with rollback on
  failure, and stale parked copies are swept on the next launch.
- New: `install.ps1` — the PowerShell installer
  (`irm https://www.sevrahq.com/install/sevra.ps1 | iex`), same contract as
  `install.sh`: required SHA-256 from Sevra's independently deployed release
  manifest, plus fail-closed Ed25519 verification when Node or OpenSSL 3 is
  available. It honors
  `SEVRA_INSTALL_DIR` / `SEVRA_VERSION` / `SEVRA_INSTALL_BASE` /
  `SEVRA_TRUSTED_MANIFEST_BASE`, installs to `~\.sevra\bin`, no admin rights.
- CI: the full test suite now also runs on `windows-latest` on every push
  (the release target's continuous guard), and the post-release smoke
  installs on Windows via `install.ps1` alongside the unix jobs.
- Account keys read `sevra_account_*` in every hint and doc (the hub mints
  that prefix now; legacy `vc_account_*` keys keep validating), `login`
  normalizes the bare apex hub host to www (a 308 strips the bearer, which
  read back as a misleading 401), and the installer error strings dropped
  their em dashes.
- Large brains now push and export through deterministic, content-addressed
  ZIP packs instead of failing at the JSON request-body ceiling. Snapshots
  cap at 100,000 files, 512 MB uncompressed, and 256 MB compressed. Pack
  downloads are SHA-256 verified and fully path/type/duplicate/size checked
  before the first filesystem write; existing symlink escapes are refused.
- Hub URLs use a real authority parser and reject userinfo, query, fragment,
  and non-HTTPS remote origins. Authenticated and presigned traffic refuses
  redirects, so credentials and pack bytes cannot be steered to a second
  origin. Presigned requests never carry the hub bearer.
- The Unix and Windows installers require the release digest from Sevra's
  independently deployed manifest for ordinary GitHub downloads. A present
  Ed25519 verifier now fails closed on a bad signature; only hosts with no
  verifier at all use the independently trusted digest as their sole check.

## 0.1.4 — 2026-07-13

- New: `sevra secrets list|set|delete <brain> [NAME]` — the vault: write-only
  secret values bound to a brain's published functions
  (https://www.sevrahq.com/docs/publishing.md, "Functions + the vault").
  `list` shows provisioned names plus each function's live state, declared
  secrets, and egress allowlist; `set` provisions or rotates one value;
  `delete` unbinds and forgets it.
- The `set` security contract, locked by tests:
  - the VALUE is read from stdin only — a no-echo prompt on the controlling
    terminal (via /dev/tty, so `--json` stdout stays clean) when stdin is a
    TTY, else the whole pipe with exactly ONE trailing newline trimmed
    (`printf %s "$V" |` and `echo "$V" |` deliver the same value; multi-line
    values like PEM keys pass through intact);
  - the value is never accepted from argv: a trailing positional or a
    `--value` flag is refused as a usage error (exit 2) WITHOUT being echoed
    — clap's own unexpected-argument error would have printed it (hidden
    trap arguments absorb both shapes first);
  - the value appears nowhere in stdout/stderr on any path — success,
    refusals, transport failures, `--json` included;
  - names are clap-validated to the hub's exact gate (^[A-Z][A-Z0-9_]{0,63}$)
    before any I/O; empty and >4096-char values are refused client-side with
    messages that name sizes, never bytes;
  - `set` fails "not logged in" BEFORE reading the value (never ask for a
    secret the process cannot send).
- New dependency: rpassword (Apache-2.0, with rtoolbox) for the no-echo
  terminal read; recorded in THIRD_PARTY_NOTICES.
- `usage_fail` joins the output contract: post-parse usage errors exit 2 like
  clap's own, keeping the documented 1-vs-2 split for agents.

## 0.1.3 — 2026-07-11

Adversarial-review round three (two independent fresh-eyes reviews + an
empirical edge-case pass).

Security:

- A malformed API key can no longer leak into output. A key with a bad byte
  (e.g. an interior control character) used to reach ureq's header
  validation, whose error echoed the ENTIRE authorization header — key
  included — onto stdout/stderr. Keys are now whitespace-trimmed (the classic
  trailing-newline paste artifact just works) and charset-checked before any
  header is built; refusal messages never echo the key. Locked by a test.
- Release builds no longer restore a mutable build cache (a poisoning vector
  for bytes that get signed).
- cargo-deny now also enforces the `[sources]` policy in CI (unknown
  registries/git sources were declared denied but the check never ran).
- The `workflow_dispatch` version input is env-bound, not interpolated into
  the script.
- ci/audit/smoke workflows run with least-privilege `contents: read`.
- install.sh honors `SEVRA_REQUIRE_SIGNATURE=1`: fail the install when the
  Ed25519 check cannot run here, instead of relying on SHA-256 + HTTPS alone.

Correctness and honesty:

- `logout` is honest: reports removal, reports "no stored credential", and
  FAILS LOUDLY when the credential file exists but cannot be removed
  (previously it always claimed success while the key stayed on disk).
- `--json` now holds for clap's built-in `--version` and `--help` (they
  printed human text on stdout under --json).
- In `--json` failures, the `error` field is always sevra's formatted message
  (status + context); a hub body carrying its own `error` key no longer
  clobbers it.
- An oversized release asset fails as "asset exceeds 64 MB" instead of
  surfacing as a false signature-verification alarm.
- `validate` on a regular file says "directory not found" instead of
  misreporting that dbmd is not installed.
- `inbox` action and `graph --dir` are clap-validated (usage errors, exit 2,
  self-documenting help); `query --limit` is a real integer argument.
- RELEASING.md now states the signing-secret encoding exactly (base64 of the
  PKCS#8 PEM) with the command — following the old text on key rotation
  would have broken the sign step with ERR_OSSL_UNSUPPORTED.
- README no longer claims `SEVRA_NO_AUTO_UPDATE=1` prints a notice (it
  disables the check entirely, as the code and llms.txt already said);
  SECURITY.md states precisely what SHA-256 vs Ed25519 each prove.
- MSRV is now enforced by a CI job instead of merely claimed — which
  immediately falsified the claim: the locked tree's true floor is 1.88
  (home 0.5.12; base64ct is edition2024), so the declared MSRV is corrected
  1.82 → 1.88.
  `ring` is attributed as Apache-2.0 AND ISC in THIRD_PARTY_NOTICES.
- store-walk unit tests (cap boundary, dotfile skip, symlink-cycle dedup,
  named non-UTF8 errors); 27 tests total.

## 0.1.2 — 2026-07-11

Adversarial-review round two.

- Hub responses are read through an explicit 256 MB-capped reader; previously
  `into_string()` silently stopped at ureq's 10 MB limit, which broke
  `sevra export` on large brains with a misleading "non-JSON body" error.
  Over-cap and mid-body read failures now fail with honest messages.
- Release signing moved to the publish job: the signing key is now used only
  in a job whose sole pre-signing action is first-party
  (actions/download-artifact) — build jobs and their third-party actions never
  see the secret. Workflow permissions dropped to least-privilege.
- The release workflow refuses any version that differs from Cargo.toml
  (previously only tag pushes were checked; a workflow_dispatch typo could
  ship binaries that self-report older than "latest" and re-download daily).
- `export` refuses to write through a pre-existing symlink at the leaf
  (completes the containment story: parent dirs were already re-checked).
- The version string from the hub is charset-validated before it is
  interpolated into the release-download URL (it could never pass signature
  verification, but it must not steer the URL either).
- `sevra update` reports "could not report the latest release" instead of
  "already up to date" when the hub cannot resolve a latest version.
- `http://[::1]:<port>` now correctly counts as loopback for the HTTPS guard.
- `push` read errors name the offending file (a UTF-8 error in a 10k-file
  vault was undebuggable).
- install.sh: the whole script runs through `main()` (a truncated
  `curl | sh` can never execute a partial script) and the final install is an
  atomic same-filesystem rename (no half-written binary window on reinstall).
- README states the installer's signature verification precisely (SHA-256
  always; Ed25519 when node or openssl 3 is present).

## 0.1.1 — 2026-07-10

- The daily auto-update check is throttled to once per 24h
  (`~/.sevra/update-check`); previously every hub command fetched the
  versions endpoint. `SEVRA_NO_AUTO_UPDATE=1` now skips the check entirely
  (zero extra requests).
- Network timeouts everywhere (10s connect / 120s read): a hung endpoint can
  no longer hang an agent's loop.
- `sevra help` works as a subcommand (parity with `--help`).
- Repo hygiene to the dbmd bar: `THIRD_PARTY_NOTICES`, `SECURITY.md`,
  `RELEASING.md`, `llms.txt`, a scheduled dependency-audit workflow, and a
  post-release install smoke workflow.
- Adversarial-review fixes: the auto-update download is DEFERRED until after
  the command's output (it can never delay an answer); `sevra validate`
  forwards `--json` to dbmd; clap usage errors emit JSON under `--json`;
  `~/.sevra/config.json` is 0600 from creation (no chmod window); `push`
  refuses oversized stores during the walk (no read-then-check OOM);
  `export` re-checks real paths against symlinked subdirs in existing target
  dirs; `login` honors `SEVRA_API_KEY` as its message promised; a failed
  self-update write cleans up its temp file.

## 0.1.0 — 2026-07-10

- First Rust release: the full sevra command surface as a signed,
  self-updating, zero-runtime static binary (macOS + Linux, x86_64 + arm64).
  Replaces the TS single-file CLI at parity (proven against the hub's
  91-check production battery).
