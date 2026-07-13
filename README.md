# sevra

The command line for the [Sevra hub](https://www.sevrahq.com): the managed home for db.md brains.

A brain is a database in plain files ([db.md](https://github.com/carloslfu/db.md)) that your own AI operates. Sevra keeps it alive, organized, indexed, and reachable. This CLI is how an agent works with a hosted brain: push a local store, query it back, publish pages, share access.

It is a single static binary. No runtime, no package manager, no dependencies. It installs on any machine an agent runs on.

## Install

```sh
curl -fsSL https://www.sevrahq.com/install/sevra.sh | sh
```

macOS and Linux, x86_64 and arm64. On Windows use WSL. The installer verifies the download's SHA-256 always, and its Ed25519 publisher signature when node or openssl 3 is present, before placing the binary on your PATH. The binary itself re-verifies the signature on every self-update.

## Commands

```
sevra login --key <vc_account_…> [--hub <url>]   store your credential
sevra logout
sevra whoami

sevra brains                                     list your brains
sevra create <slug> [--name] [--scope] [--public]
sevra push <dir> --brain <id|slug>               index-on-push
sevra query <brain> [text] [--type] [--layer] [--meta-type] [--tag] [--where k=v] [--limit N]
sevra get <brain> <db.md-id|path>
sevra graph <brain> <path> [--dir in|out|both]

sevra grant <brain> <email> [--write]
sevra grants <brain>
sevra revoke <brain> <grantId>
sevra shared                                     brains shared with you
sevra publish <brain>                            render public records to <handle>.sevra.page
sevra unpublish <brain>                          pull all public pages
sevra secrets list <brain>                       the vault: secret names + function bindings
sevra secrets set <brain> NAME                   value from stdin (hidden prompt / pipe), write-only
sevra secrets delete <brain> NAME                unbind + forget one secret
sevra inbox list|drain <brain>                   read the evidence inbox (drain = full JSON)
sevra export <brain> [dir]                       write your brain back to disk (you own it)

sevra validate [dir]                             wraps `dbmd validate --all`
sevra version
sevra update                                     signed self-update; checks dbmd too
```

Config lives at `~/.sevra/config.json` (written 0600). Env `SEVRA_HUB_URL` / `SEVRA_API_KEY` override it.

`secrets set` binds a write-only value to the brain's published functions ([the vault](https://www.sevrahq.com/docs/publishing.md)). The value is read from stdin only — a hidden prompt on a terminal, or piped (`printf %s "$VALUE" | sevra secrets set <brain> NAME`, exactly one trailing newline trimmed). It is never accepted on the command line and never echoed back, on any path.

## Built for agents

sevra is a machine interface. Add `--json` to any command for machine-readable output on stdout, always, including errors. Error messages are written as instructions an agent can act on. Notices go to stderr and never corrupt `--json` parsing.

## Updates and signing

Every release binary is signed (Ed25519) and published to GitHub Releases with a `SHA256SUMS` manifest. `sevra` checks the hub for a newer release at most once a day and updates itself: it downloads the platform asset, verifies the signature against the key pinned in the binary, and atomically replaces its own file. The running command finishes on its loaded code; the new version applies next run. `SEVRA_NO_AUTO_UPDATE=1` disables the check entirely (no request, no notice); run `sevra update` explicitly instead (it also reports when your local `dbmd` is behind).

The publisher public key is in [`sevra.pub`](sevra.pub) and served at [`/install/sevra.pub`](https://www.sevrahq.com/install/sevra.pub) for out-of-band verification.

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
