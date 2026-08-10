# sevra

The command line for the [Sevra hub](https://www.sevrahq.com): the managed home for db.md brains.

A brain is a database in plain files ([db.md](https://github.com/carloslfu/db.md)) that your own AI operates. Sevra keeps it alive, organized, indexed, and reachable. This CLI is how an agent works with a hosted brain: push a local store, query it back, publish pages, share access.

It is a single static binary. No runtime, no package manager, no dependencies. It installs on any machine an agent runs on.

## Install

macOS and Linux (x86_64 and arm64):

```sh
curl -fsSL https://www.sevrahq.com/install/sevra.sh | sh
```

Windows (native x64; ARM64 runs the same binary under the built-in emulation):

```powershell
irm https://www.sevrahq.com/install/sevra.ps1 | iex
```

Both installers verify the download's SHA-256 against Sevra's independently deployed release manifest. When Node or OpenSSL 3 is present, they also require a valid Ed25519 publisher signature before placing the binary on your PATH. Set `SEVRA_REQUIRE_SIGNATURE=1` to refuse installation when neither verifier is available. The binary itself requires both the signature and the independent Sevra digest on every self-update.

## Commands

```
sevra login [--hub <url>]                        approve in the browser (default)
sevra login --key <sevra_account_…> [--hub <url>]   or store a key directly
sevra logout                                     revoke a browser-minted key + forget it
sevra whoami

sevra brains                                     list your brains
sevra create <slug> [--name] [--scope] [--public]
sevra delete <brain> [--confirm <slug>]          permanently delete a hosted brain (owner-only)
sevra clone <brain> [dir]                        records + assets + sync baseline into a fresh dir
sevra pull [dir] [--force]                       refresh a clone; refuse local divergence by default
sevra push <dir> --brain <id|slug> [--force]     replace the hosted store with <dir> (index-on-push)
sevra query <brain> [text] [--type] [--layer] [--meta-type] [--tag] [--where k=v] [--limit N]
sevra query --brain <ref> [text] …               the same query, brain as a flag
sevra get <brain> <db.md-id|path>
sevra graph <brain> <path> [--dir in|out|both]
sevra mcp                                        serve your brains to MCP clients (stdio, read-only)

sevra grant <brain> <email> [--write]
sevra grants <brain>
sevra revoke <brain> <grantId>
sevra shared                                     brains shared with you
sevra publish <brain>                            render public records to <handle>.sevra.page
sevra unpublish <brain>                          pull all public pages
sevra secrets list <brain>                       the vault: secret names + function bindings
sevra secrets set <brain> NAME                   value from stdin (hidden prompt / pipe), write-only
sevra secrets delete <brain> NAME                unbind + forget one secret
sevra secrets scan [dir]                         the push secret scan, read-only (exit 1 on matches)
sevra secrets quarantine [dir] [--dry-run] [--closure]   keep hit files home in .sevralocal
sevra inbox list|drain <brain>                   read the evidence inbox (drain = full JSON)
sevra export <brain> [dir]                       write your brain back to disk (you own it)

sevra validate [dir]                             wraps `dbmd validate --all`
sevra version
sevra update                                     signed self-update; checks dbmd too
```

Config lives at `~/.sevra/config.json` (written 0600). Env `SEVRA_HUB_URL` / `SEVRA_API_KEY` override it.

`clone` is the first-machine or second-machine path. It verifies the hosted pack and every declared asset, installs the complete store through a private stage into a fresh directory, then records `.sevra-sync.json`: the brain identity, feed sequence and hash, pack SHA-256, and per-path digests. `pull` checks local path digests before its first request, refuses to overwrite divergence while naming the changed paths, uses the cheap brain-head call for a no-op, and otherwise requests that exact feed snapshot. `pull --force` is the explicit discard-local-work path. `.sevralocal` files and the content they keep home are preserved. A per-store lock and durable private recovery journal make the in-place commit restart-safe: if the process dies between path replacements, the next push or pull restores the complete old snapshot before contacting the hub; if the last-write baseline landed, it finishes cleanup instead.

`push` replaces the brain's whole hosted store with the pushed directory: files absent locally are removed, and a push that would shrink the brain's document count is refused unless `--force` is given. A successful push writes or advances the same local baseline. Subsequent pushes send the expected feed sequence, and the hub refuses under its durable write lock if another machine advanced first. Pull, reconcile, then push; use `--force` only when replacing the newer hosted state is intended. Before anything uploads, the store is checked locally against the hub's snapshot limits (256 MiB compressed, 512 MiB uncompressed, 100,000 files; refusals list the largest files) and scanned for secret-shaped markdown, asset bytes, and names (AWS, GitHub, Anthropic, OpenAI, Slack, Google, Stripe key formats, PEM private-key blocks, 1Password share links). Asset inspection verifies the manifest length and SHA, scans valid UTF-8 up to 8 MiB per asset and 64 MiB total, honors `.sevralocal`, and reports everything it skips. Matches inside longer identifier runs do not count. `--allow-secrets` overrides the scan; `--skip-assets` omits asset bytes and therefore their byte scan. `delete` is permanent: interactive runs ask for the brain's slug, scripts pass `--confirm <slug>`.

A `.sevralocal` file at the store root keeps files home: one store-relative path or glob per line (`#` comments, blank lines skipped; matched byte-wise and case-sensitively against the pushed paths). Matching files are part of the brain but never part of the cargo — push leaves them on the machine and reports how many stayed home, and while the list has entries every derived `index.md` catalog stays home too (catalogs carry every file's name and summary, kept-home ones included; the hub rebuilds its own). The list itself never uploads. `DB.md` and `assets.jsonl` always ride: a list that covers either (including via a broad glob like `**`) is refused.

`secrets scan [dir]` runs push's secret scan read-only (exit 1 on matches, 0 clean; matched values never shown). `secrets quarantine [dir]` appends each hit file's exact path to `.sevralocal`, creating it when absent — the third exit besides editing files and `--allow-secrets`. `--dry-run` previews; `--closure` also marks every file connected to a marked one through wiki-links (computed via `dbmd emit`). Kept-home is forward-only: marking changes future snapshots and erases nothing by itself. Retained packs keep bytes that already rode; a kept-home asset remains declared so its blob is not swept; retention-locked backups persist for about 31 days. Rotate at the issuer immediately. Byte erasure requires `sevra delete`, completion of the sweep and backup-retention window, then a fresh push. The only file sevra ever edits is `.sevralocal`, and only by appending.

`secrets set` binds a write-only value to the brain's published functions ([the vault](https://www.sevrahq.com/docs/publishing.md)). The value is read from stdin only — a hidden prompt on a terminal, or piped (`printf %s "$VALUE" | sevra secrets set <brain> NAME`, exactly one trailing newline trimmed). It is never accepted on the command line and never echoed back, on any path.

`mcp` serves the hub's read surface (list_brains, search_brain, get_record, graph) to any MCP client over stdio — for agents that cannot run a CLI. Configure the client with `{"command": "sevra", "args": ["mcp"]}`. It uses the stored sign-in (env `SEVRA_API_KEY` / `SEVRA_HUB_URL` override it); without one it reaches public brains only. stdout carries only JSON-RPC frames; notices go to stderr.

## Built for agents

sevra is a machine interface. Add `--json` to any command for machine-readable output on stdout, always, including errors. Error messages are written as instructions an agent can act on. Notices go to stderr and never corrupt `--json` parsing.

## Updates and signing

Every release binary is signed (Ed25519), covered by keyless GitHub/Sigstore provenance, and published to an immutable GitHub Release with a `SHA256SUMS` manifest. Verify a downloaded binary with `gh attestation verify <binary> --repo sevrahq/sevra`. `sevra` checks the hub for a newer release at most once a day and updates itself: it downloads the platform asset, verifies the signature against the publisher keys pinned in the binary, requires the independently deployed Sevra digest to match, and atomically replaces its own file. The running command finishes on its loaded code; the new version applies next run. `SEVRA_NO_AUTO_UPDATE=1` disables the check entirely (no request, no notice); run `sevra update` explicitly instead (it also reports when your local `dbmd` is behind).

The active publisher trust set is in [`sevra.pub`](sevra.pub) and served at [`/install/sevra.pub`](https://www.sevrahq.com/install/sevra.pub) for out-of-band verification.

## Build from source

```sh
cargo build --release   # target/release/sevra
make check              # fmt + clippy + test
```

Rust 1.88+. The dependency tree is permissive-licensed only, enforced by `cargo deny`.

## Related

- [db.md](https://github.com/carloslfu/db.md): the open standard for databases in plain files. The `dbmd` CLI is the neutral tool for the format; sevra wraps it (via `validate`) and never reimplements it.
- [Sevra](https://www.sevrahq.com): the hub. The home is free.

## License

MIT. Copyright (c) 2026 VibeCraft Inc.
