# Changelog

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
