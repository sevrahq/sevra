# sevra

The command line for the [Sevra hub](https://www.sevrahq.com): the managed home for db.md brains.

A brain is a database in plain files ([db.md](https://github.com/carloslfu/db.md)) that your own AI operates. Sevra keeps it alive, organized, indexed, and reachable. This CLI is how an agent works with a hosted brain: push a local store, query it back, publish pages, share access.

## Install

```sh
curl -fsSL https://www.sevrahq.com/install/sevra.sh | sh
```

Requires Node.js 18+. One self-contained file lands on your PATH. No packages, no dependencies, nothing else installed.

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
sevra inbox list|drain <brain>                   read the evidence inbox (drain = full JSON)
sevra export <brain> [dir]                       write your brain back to disk (you own it)

sevra validate [dir]                             wraps `dbmd validate --all`
sevra version                                    print this build's stamp
sevra update                                     self-replace with the hub's current build
```

Config lives at `~/.sevra/config.json`. Env `SEVRA_HUB_URL` / `SEVRA_API_KEY` override it.

## Built for agents

sevra is a machine interface. Add `--json` to any command for machine-readable output on stdout, always, including errors. Error messages are written as instructions an agent can act on. Informational notices go to stderr and never break parsing.

## How updates work

sevra is versionless: the deploy is the release. Every build carries a stamp (the short git sha). The CLI compares its stamp against the hub on every call and replaces its own file when the hub runs a newer build. The running command finishes untouched; the new build applies on the next run. Set `SEVRA_NO_AUTO_UPDATE=1` to get a one-line notice instead. `sevra update` updates explicitly and also reports when your local `dbmd` is behind.

## Signing

Every served build is signed (Ed25519, detached signature). The installer verifies before installing. The CLI verifies before every self-update and refuses anything that fails. The public key is pinned in the installer and the CLI, served at [`/install/sevra.pub`](https://www.sevrahq.com/install/sevra.pub), and included in this repo as [`sevra.pub`](sevra.pub).

Verify out of band:

```sh
curl -sO https://www.sevrahq.com/install/sevra.cjs
curl -sO https://www.sevrahq.com/install/sevra.cjs.sig
node -e '
const { createPublicKey, verify } = require("node:crypto");
const { readFileSync } = require("node:fs");
const ok = verify(null, readFileSync("sevra.cjs"),
  createPublicKey(readFileSync("sevra.pub")),
  Buffer.from(readFileSync("sevra.cjs.sig", "utf8").trim(), "base64"));
console.log(ok ? "valid" : "INVALID"); process.exit(ok ? 0 : 1)'
```

## Source of truth

This repo mirrors the canonical source in the Sevra platform repo on every change. The served artifact at `/install/sevra.cjs` is transpiled from [`sevra.ts`](sevra.ts) on every deploy, stamped, and signed. A Rust port with the same signed self-update chain is planned and will land in this repo.

Issues and feedback are welcome here.

## Related

- [db.md](https://github.com/carloslfu/db.md): the open standard for databases in plain files. The `dbmd` CLI is the neutral tool for the format; sevra wraps it and never reimplements it.
- [Sevra](https://www.sevrahq.com): the hub. The home is free.

## License

MIT. Copyright (c) 2026 VibeCraft Inc.
