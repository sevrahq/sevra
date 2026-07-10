# Changelog

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
