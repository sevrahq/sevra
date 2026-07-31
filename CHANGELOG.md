# Changelog

## 0.2.8 — 2026-07-30

- Security: publisher-key rotation starts with an additive compatibility
  release. The updater and both installers trust the original and successor
  Ed25519 keys, while v0.2.8 remains signed by the original key. The
  independently deployed SHA-256 manifest is still mandatory, so accepting
  either publisher key does not collapse the second trust root.
- Security: `secrets quarantine` refuses a symlinked `.sevralocal`, opens an
  existing scope file with the kernel's no-follow flag on Unix, rejects
  control-bearing file names that cannot be represented by its line format,
  escapes leading `#` names so they cannot become comments, and installs
  updates through a synced same-directory atomic replacement.
  A cloned store can no longer turn quarantine into a write through a
  dangling shell-startup-file symlink or inject extra startup-file lines.
- Security: `.sevralocal` is capped at 1 MiB, 4,096 bytes per line, and
  10,000 effective entries. The reader checks the held file's size and reads
  one bounded sentinel byte, so sparse files and concurrent growth fail before
  allocation, network access, or scope mutation.
- Security: asset push refuses every symlink component, and export restore
  refuses symlink leaves or parents outside the export before downloading.
  Unix reads and writes traverse from held directory descriptors with
  `O_NOFOLLOW`; Windows holds every ancestor without delete sharing and rejects
  every reparse point. Restored bytes are installed by atomic replacement
  under the held parent. An ancestor planted during the presign round-trip
  cannot redirect a verified blob onto an unrelated file.
- Security: the same capability boundary now covers every markdown export,
  the export root itself, the push walker, config credentials, and the
  auto-update stamp. Logout also removes the credential through the held
  config-directory handle rather than following a replaced `~/.sevra`.
  Push opens directories and files from held parents and sends the exact bytes
  read from those handles. Symlinks in a store are refused, including links
  whose target is still inside the store.
- Security: export validates the complete portable path manifest before its
  first write. It rejects file/directory prefix collisions, case aliases,
  Windows device names, alternate data streams, backslashes, and trailing
  dots or spaces on every host. Existing destination types are fully
  preflighted, and a later write failure restores every attempted file from a
  bounded transaction snapshot.
- Security: presigned asset/pack transfers resolve through a client-owned
  network policy that rejects loopback, private, link-local, carrier-grade NAT,
  and metadata destinations, including DNS rebinding. Loopback transfer is
  available only when the configured hub is itself loopback. Export
  decompression now caps the byte stream instead of trusting a ZIP entry's
  declared uncompressed length. Asset upload and restore now stream through
  bounded private stages instead of whole-blob RAM buffers, enforce the hub's
  2 GiB per-object ceiling independently of manifest metadata, reject sparse
  oversize inputs before reading, and require exact length plus SHA-256 before
  upload or atomic installation.
- Security: both installers stage through freshly created unpredictable
  directories instead of PID-derived leaves. A custom binary mirror must name
  a separate trusted-manifest endpoint; its colocated `SHA256SUMS` can no
  longer become its own trust root on a machine without a signature verifier.
  The Unix installer also rejects every symlink component and unsafe
  destination type before a cwd-bound same-directory rename. The Windows
  installer holds every directory component through no-follow handles without
  delete sharing, rejects reparse points, and replaces only through
  `MoveFileExW`.
- Security: human stdout/stderr neutralizes ANSI, OSC, carriage return,
  backspace, BEL, and other terminal controls from hub/store text. JSON output
  retains the original data through JSON escaping.
- Security: self-update now requires the independently deployed Sevra digest
  in addition to the Ed25519 signature. An unavailable or malformed second
  root refuses the update instead of silently falling back to one key.
- Supply chain: release tags must point to `main`; a guarded wrapper requires
  clean `main`, exact `origin/main`, and green CI before tagging. v0.2.8 alone
  uses a protected runner authorization bound to its exact tag, commit,
  workflow attempt, and nonce, then deletes the transitional signer.
  Successor signing moves entirely off hosted runners: Actions emits five
  unsigned, tag/SHA-attested binaries; the local controller independently
  rebuilds and byte-compares every target before reading the 1Password signer
  over stdin-only process memory, then uploads a complete draft and publishes
  it immutable. It verifies checksums, exact assets, tag target, and binary
  provenance after publication.
- Supply chain: the release controller can resume only when the remote tag
  still names the authorized commit and exactly one workflow run names that
  tag and SHA. Completed immutable releases are verification-only. Interrupted
  drafts are rebuilt as complete sets. Ephemeral-secret cleanup is armed before
  injection starts and covered by a hermetic interruption regression.
- Integrity: large pushes use one cross-language canonical ZIP32 profile:
  path-byte sorting, STORED members, fixed metadata, and no extras, comments,
  descriptors, or ZIP64. Sevra and the hub share a byte-level golden vector,
  so the signed store hash identifies one exact archive rather than one of
  several equivalent encodings.
- Supply chain: release builds pin Ubuntu 24.04, macOS 26, Rust 1.96.0,
  `cross` 0.2.5 with digest-pinned Linux images, and cargo-xwin 0.23.0 by
  archive SHA-256 with fixed Windows SDK/CRT versions. Any hosted/local byte
  mismatch, including platform nondeterminism, fails closed before signing.
  Canonical path/time inputs plus Windows `/Brepro` without CodeView/PDB make
  clean local double-builds byte-identical on all five targets.
- Installers: `SEVRA_REQUIRE_SIGNATURE=1` once again fails closed when no
  capable verifier is present, with executable negative tests on Unix and
  Windows. Post-manifest smoke also proves the production installers remain
  byte-identical to this repository.
- Supply chain: post-manifest smoke proves production still routes legacy
  old-key-only CLIs through v0.2.8 before offering successor-signed releases,
  and the release runbook deploys changed installer snapshots before the
  byte-identity smoke gate.

## 0.2.7 — 2026-07-30

Your brain is more than markdown — the bytes ride too. 0.2.6 and every
release before it pushed the manifest and left the blobs home; the hub's
content-addressed asset transport had no client. Now it does.

- New: **push syncs asset bytes.** After a committed snapshot, `sevra push`
  asks the hub which `assets.jsonl`-declared hashes are still missing and
  ships each one through the content-addressed flow — presign
  (quota-reserved) → exact-length checksummed PUT → confirm. Blobs dedupe on
  hash, re-pushes skip everything already present, `.sevralocal` kept-home
  paths never leave the machine, and a locally missing or drifted file is
  named and skipped, never a stranded push. `--skip-assets` opts a push out.
- New: **export restores asset bytes.** `sevra export` reads the exported
  manifest and downloads every absent (or drifted) blob beside the store —
  each SHA-256-verified and containment-checked before it is written.
  `--skip-assets` opts out. Export round-trips the whole brain: markdown,
  manifest, and bytes.
- Changed: presigned transfer URLs now honor the SAME loopback exemption as
  every hub URL (`assert_safe_hub`): HTTPS everywhere, plain HTTP only to
  the caller's own machine — which also lets the mock-hub suite cover the
  real byte path end to end.
- Note: the hub's single-push markdown ceiling returned to the 512 MiB
  pack-format bound (streaming ingest landed hub-side), so the CLI's
  existing 512 MiB store preflight is again the same number the hub
  enforces — one limit, both sides.

## 0.2.6 — 2026-07-30

- Security: push and secret scanning now refuse any file or directory symlink
  whose resolved target is outside the selected store. A hostile cloned brain
  can no longer smuggle a sibling tree, home-directory credential, or other
  external Markdown file into a snapshot. In-store links still work, while
  real-path deduplication keeps cycles and aliases bounded.
- Fixed: large pack commits receive a verb-specific 330-second deadline,
  matching the hub's 300-second unpack, validation, indexing, and publication
  budget. Healthy large-brain commits no longer fail at the CLI's generic
  120-second read timeout.
- Security: the self-updater creates its staged binary without following a
  pre-planted symlink, and Windows browser sign-in launches Explorer directly
  instead of sending a URL through `cmd /C start`. Store entries with
  non-UTF-8 names are refused rather than being lossily renamed into an
  ambiguous upload path.
- Security: MCP stdio frames are capped at 1 MiB and piped secret input is
  byte-bounded before UTF-8 decoding. Malformed local peers can no longer grow
  the long-lived MCP process or a secret command without limit.

## 0.2.5 — 2026-07-28

Secrets get a place that is not the hub. 0.2.4's scan left two exits — edit
the files or `--allow-secrets` — and both punish keeping real credentials in
the brain. 0.2.5 adds the right one: keep them home. Files marked kept-home
are part of the brain but never part of the cargo.

- New: **`.sevralocal` — the store's local scope.** One store-relative path
  or glob per line at the store root (`#` comments and blank lines skipped;
  matching is byte-wise and case-sensitive against the same POSIX paths the
  push walk computes). Matching files are excluded from the push and counted
  separately: "N file(s) kept home (.sevralocal)". They do not count toward
  the hub's snapshot limits — they never ride. The list itself never uploads
  (the walk's dot-skip, now pinned by a test). While the list has at least
  one effective entry, every derived `index.md` catalog stays home too:
  catalogs carry every file's name/title/summary, kept-home ones included,
  and the hub rebuilds its own from what rides. `DB.md` and `assets.jsonl`
  must always ride: a list whose compiled set covers either — which also
  catches broad globs like `**` — refuses push and quarantine both; a secret
  inside those two is an edit case the scanner already flags.
- New: **`sevra secrets scan [dir]`** — push's secret scan as a read-only,
  offline report (no login): same patterns, same refusal shape (`--json`
  carries `secretHits` capped at 20, `total`, and the `error` string), exit
  1 on matches and 0 clean. Matched values are never shown. It honors
  `.sevralocal`, reporting exactly what a push would carry.
- New: **`sevra secrets quarantine [dir]`** — scan the FULL store (kept-home
  files included) and append each hit file's exact path to `.sevralocal`,
  creating it when absent; existing lines are preserved verbatim, new
  entries append sorted, single trailing newline. Idempotent — a re-run
  appends nothing and exits 0; `--dry-run` previews. Every run states the
  forward-only truth: files that already rode a push remain in earlier
  snapshots; marking removes them from the next snapshot and erases
  nothing. It warns — and never acts — when the FILENAME is the secret
  (consider renaming; a future feed removal would record the name, path
  shown redacted) and when the asset manifest names kept-home files (the
  manifest rides; removing entries is the operator's deliberate edit). It
  never marks `DB.md` or `assets.jsonl`. The only file sevra ever edits is
  `.sevralocal`, and only by appending.
- New: **`quarantine --closure`** — also keep home every file connected to a
  marked one through wiki-links (the undirected component over the content
  graph from `dbmd emit --json`; catalogs and the store config are never
  bridges, so nothing over-marks through derived files). Requires `dbmd`; a
  missing binary fails up front, before anything is written. Every path
  closure adds is printed. Works with `--dry-run`.
- `push` integration: the secret refusal now names the three exits in
  order — `sevra secrets quarantine <dir>` (keep these files home) · edit
  the files yourself · `--allow-secrets` (push them verbatim). A shrink
  refusal (hub 409) appends the line that explains kept-home documents. A
  store where everything is kept home refuses with the count instead of the
  bare empty-store error. `push --help` documents `.sevralocal`.
- New dependency: globset (MIT/Unlicense, the regex family; adds bstr) for
  `.sevralocal` matching; recorded in THIRD_PARTY_NOTICES.

## 0.2.4 — 2026-07-28

Fixes from the first dogfood onboarding (2026-07-28), against the hub's new
push/delete contract.

- New: **`push` scans for secrets before anything leaves the machine.**
  Every file that would be pushed is checked — content AND path, since a
  secret in a filename lands in the hub index and feed — against a
  conservative set of vendor-prefixed formats (AWS access key ids, GitHub
  tokens, Anthropic/OpenAI/Google/Stripe-live keys, Slack tokens, PEM
  private-key blocks, 1Password share links). On hits the push is refused,
  naming each hit as `path — kind` with a remediation line; the matched
  value is never printed, and a path that itself matches is shown redacted.
  `--allow-secrets` overrides. No binary handling was needed: push carries
  only UTF-8 text (`.md` + the root `assets.jsonl`), so the content pass
  covers every byte that would ship.
- New: **`push` preflights the hub's snapshot limits locally** — 256 MiB
  compressed pack, 512 MiB uncompressed, 100,000 files — and never starts an
  upload the hub must reject. A refusal names the limit, the store's actual
  numbers, and the 10 largest files with human sizes, and suggests trimming
  sources/ or splitting a deliberately large store. The over-size walk keeps
  counting (metadata-only) past the cap so the reported totals are real.
- New: **`push --force` sends `allow_shrink`** on both the JSON push and the
  pack commit. `push --help` now states plainly that push REPLACES the
  brain's whole hosted store (files absent locally are removed). Without
  --force, the hub's 409 `shrink_refused` answer is printed verbatim plus
  one hint: retry with --force if the replacement is intended.
- New: **`sevra delete <brain>`** — permanent, owner-only. Interactive runs
  show what dies and require typing the brain's slug; non-TTY or `--json`
  runs must pass `--confirm <slug>`. The hub's 400 `confirm_required` maps
  to the exact rerun command.
- Fixed: **`query` accepts `--brain <ref>`** as an alias of the positional
  (push already spelled the brain that way; `sevra query --brain X "text"`
  was an "unexpected argument" usage error). Both forms naming different
  brains is a clear exit-2 refusal.
- Fixed: pack-flow errors no longer collapse to `unknown error`. Wherever a
  hub answer carries a JSON `error`, that message (plus its `code`) is
  printed; a non-JSON body (proxy page, HTML) surfaces its first ~200 chars.
  Presigned upload/download failures now include the storage service's
  answer instead of a bare status code. A 507 `hub_scratch_exhausted` on the
  pack commit retries the commit twice after a pause — the pack is already
  uploaded and is never re-sent.
- New dependency: regex (MIT/Apache-2.0, with aho-corasick +
  regex-automata/-syntax) for the compiled secret-pattern set; recorded in
  THIRD_PARTY_NOTICES.

## 0.2.3 — 2026-07-18

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
