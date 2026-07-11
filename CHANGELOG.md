# Changelog

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
