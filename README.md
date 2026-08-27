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
sevra agents <brain>                             show configured agents, sources, flags, and schedule state
sevra runs <brain>                               show recent run history, outcomes, and errors
sevra run <brain> <agent>                        manually queue one Sevra-run agent
sevra create <slug> [--name] [--scope] [--public]
sevra delete <brain> [--confirm <slug>]          permanently delete a hosted brain (owner-only)
sevra clone <brain> [dir]                        clone a brain and its verified sync baseline
sevra pull [dir] [--force]                       refresh a clone (`--force` is v1-only)
sevra push <dir> --brain <id|slug> [--force]     sync local changes (`--force` is v1-only)
sevra query <brain> [text] [--type] [--layer] [--meta-type] [--tag] [--where k=v] [--limit N]
sevra query --brain <ref> [text] …               the same query, brain as a flag
sevra get <brain> <db.md-id|path>
sevra graph <brain> <path> [--dir in|out|both]
sevra mcp                                        serve brain reads and manual runs to MCP clients over stdio

sevra grant <brain> <email> [--write]
sevra grants <brain>
sevra revoke <brain> <grantId>
sevra shared                                     brains shared with you
sevra publish <brain>                            render public records to <handle>.sevra.page
sevra unpublish <brain>                          pull all public pages
sevra secrets list <brain>                       list names in the brain's server-custodied vault
sevra secrets set <brain> NAME                   create or replace a value from stdin only
sevra secrets get <brain> NAME [--reveal]        retrieve it (raw bytes when piped; TTY needs --reveal)
sevra secrets rm <brain> NAME                    permanently forget one value (`delete` also works)
sevra secrets scan [dir]                         the push secret scan, read-only (exit 1 on matches)
sevra secrets adopt [dir] [--brain <id>]         vault literals; redact markdown or derive clean text assets
sevra secrets quarantine [dir] [--dry-run] [--closure]   keep hit files home in .sevralocal
sevra inbox list|drain <brain>                   read the evidence inbox (drain = full JSON)
sevra export <brain> [dir] [--with-secrets]      write your brain back to disk (you own it)

sevra package checkpoint <workspace> --brain <brain> [--profile working]
                                                    snapshot companions + run signed incremental sync
sevra package restore <brain> <fresh-workspace> [--profile working]
                                                    clone the brain + restore companions safely
sevra package pull <workspace> [--profile working]
                                                    incrementally reconcile brain + companions
sevra package verify <workspace> [--profile working]
                                                    verify closure locally; start nothing
sevra conflicts [db-dir] [--prune] [--all]       inspect/prune private v2 conflict bundles
sevra resolve <bundle> --dir <db-dir> (--keep-local|--take-remote|--from <file>)
                                                    resolve through the stored Sevra login

sevra validate [dir]                             wraps `dbmd validate --all`
sevra version
sevra update                                     signed self-update; checks dbmd too
```

Config lives at `~/.sevra/config.json` (written 0600). Env `SEVRA_HUB_URL` / `SEVRA_API_KEY` override it.

## Brain packages

A brain package gives a hosted brain an honest, incremental recovery closure
without turning Sevra back into a machine host. The canonical profile lives in
the brain at `records/operational/sevra-package-profile.md` as one strict
`sevra-package-v1` JSON block. It names small path-dependent companions such as
agent bootstrap files, skills, scripts, templates, and service definitions,
plus typed `git`, `secret`, `path`, `live`, and `external` dependencies.
Git receipts bind a credential-free remote locator, not the moving current
commit. This avoids a self-reference when the generated package record is
committed to that same repository. Exact recovery bytes come from the signed
brain and companion-object roots; Git remains a typed source of history.
Transient worktree dirt is not a separate snapshot input: selected dirty files
are captured by content, while unselected files are outside the declared
closure. Repeated checkpoints therefore stay stable.

```sevra-package-v1
{
  "version": 1,
  "profiles": {
    "working": {
      "include": [
        { "path": "CLAUDE.md" },
        { "path": ".claude/skills" },
        { "path": "scripts" }
      ],
      "exclude": ["scripts/__pycache__"],
      "allow_secret_named_paths": [],
      "allow_unscanned_binary_paths": [".claude/skills/report/reference.pdf"],
      "dependencies": [
        { "id": "repository-history", "kind": "git", "path": ".", "remote": "origin" },
        { "id": "runtime", "kind": "path", "path": "runtime", "verification": { "kind": "directory", "required": ["config.json"] } },
        { "id": "private-brain-policy", "kind": "path", "path": "db/.sevralocal", "impact": "semantic", "verification": { "kind": "sevralocal_closure", "policy_sha256": "<sha256>", "minimum_entries": 1 } },
        { "id": "provider-key", "kind": "secret", "name": "OPENAI_API_KEY", "local_path": ".secrets/openai.json", "verification": { "kind": "regular_file" } },
        { "id": "browser-session", "kind": "live", "locator": "signed-in Chrome profile" }
      ]
    }
  }
}
```

Every field is closed-schema. Dependencies are optional unless `required` is
set to `true`; required gaps stop checkpoint/verify. Dependency `impact`
defaults to `operational`; use `semantic` only when its absence means the
restored db.md brain itself is partial. Path dependencies reject symlinks and
empty placeholders by default; profiles can require exact child coordinates,
an explicitly empty directory, or a digest-bound `.sevralocal` policy whose
every rule has restored bytes. Secret dependencies may resolve through the live
Brain Vault check or a non-empty owner-only local compatibility file. Binary
companions require exact `allow_unscanned_binary_paths` entries; directory-wide
exceptions and generated caches are refused.

`package checkpoint` reads companions without following symlinks, scans UTF-8
content and names for credentials, records portable modes and contained
symlinks, and stores each unique byte sequence at
`sources/sevra-package/objects/<sha256>.blob`. Those generated objects are
declared through db.md's ordinary asset manifest. Link.md v2 therefore uploads
only missing hashes and signs the semantic content root and asset root through
the same incremental history; there is no package archive, second baseline, or
parallel sync protocol. Normally the logical operation creates one atomic
commit. If `DB.md` changes with content, dbmd first lands and verifies the
contract-only head, then recomputes and commits the remaining tree under that
contract. The generated object directory must be Git-ignored.

`package restore` requires a fresh workspace and builds the complete result in
an unpredictable private sibling directory. It clones the brain into `db/`,
verifies the signed snapshot root, re-derives every entry and dependency against
the current profile, rescans every object, materializes files without
overwriting divergent paths, recreates only contained symlinks, and writes a
names-only vault receipt before atomically publishing the workspace without
replacement. Any pre-publication failure removes the private stage, including
a failed clone, so a failed cold restore does not strand a hidden brain copy.
It then uses db.md's explicit local-only baseline relocation to
move the verified incremental baseline from the vanished stage path to the
published `db/` path; the next ordinary `sevra pull` therefore remains
incremental and cannot mistake the moved checkout for a concurrent edit. A
long cold restore emits bounded liveness updates on stderr while
keeping JSON stdout machine-readable. It never retrieves secret values, runs a
script, starts a service, logs into an account, or claims that a live dependency
was restored. `package verify` repeats the byte, mode, symlink, object, profile,
full db.md validation, asset, and dependency checks locally and exits nonzero only for corrupt/missing
packaged state or unresolved dependencies marked `required`; optional gaps stay
visible in the structured receipt. Offline verification never treats the cached
vault-name receipt as live custody evidence. `complete` means the verified package is
safe to use under its required closure; `brainComplete` additionally requires
every semantic dependency, while `operationalReady` is strictest and is false
until every declared optional live/path/external check is resolved too. The
receipt lists `semanticUnresolvedDependencies` explicitly, so a hosted-only
copy cannot hide intentionally withheld brain content behind package success.

`package pull` is the ongoing operation for a restored working package. It
first performs the ordinary verified incremental db.md pull, then compares the
new signed package snapshot with a private, mode-600 applied-snapshot receipt.
Only file companions that still match their previous package coordinate are
updated or deleted. Divergent local companions are preserved and named; a
changed symlink topology requires a fresh restore. Updates use a private backup
journal, recheck each old coordinate during backup and immediately before
installation, and roll back after an interruption before the applied receipt
advances. A per-workspace OS lock serializes checkpoint staging, pull, recovery,
and the underlying brain operation. The receipt, lock, and journal live as
dot-prefixed local state inside `db/`, never ride sync, and must be Git-ignored.
Plain `sevra pull` remains semantic-store-only; agents maintaining a working
closure use `sevra package pull`.

Checkpoint, restore, and package pull emit a bounded 30-second liveness signal
on stderr during long verification/network phases. JSON stdout remains exactly
one machine-readable receipt, so agents can wait without guessing whether a
large brain operation is stalled.

Plain `push`, `clone`, and `export` retain their memory-store meaning. Package
commands are explicit because a customer may want semantic portability without
installing executable companions on the destination machine.

If a checkpoint meets a competing edit, it stops before overwriting anything
and returns the exact bundle id. `sevra conflicts <db-dir>` inspects the private
bundle and `sevra resolve <bundle> --dir <db-dir>` applies one explicit reviewed
choice using the existing Sevra login; agents never need to extract a bearer
credential or drop down to dbmd solely for authentication. Resolution remains
Link.md v2's exact-head operation and never acts as force.

Sevra negotiates the link.md profile with each brain. New brains use permissioned incremental v2; retained v1 brains stay readable and require an explicit verified bridge before they can change. For v2, Sevra keeps its product preflights, then delegates the wire operation to `dbmd`: the neutral client computes a private three-way baseline, uploads only changed blobs, submits the signed logical mutation, and verifies every accepted head before advancing local state. Ordinary mutations are one atomic commit; a simultaneous `DB.md` change is automatically phased into a verified contract commit followed by the recomputed content/assets commit. Deletes, renames, and restores are explicit operations with per-path authorization and expected prior hashes. Disjoint edits from two machines can rebase; competing edits to the same path stop with a conflict. `.sevra-v2.json` records only the hosted brain identity; the richer verification baseline stays outside the store in dbmd's private state. There is no force overwrite on v2.

V1 brains retain the snapshot protocol below until they receive an explicit verified bridge. The hub returns the stable `v2_sync_required` code when a v2 brain reaches a v1 transfer endpoint, and Sevra delegates only on that exact response. This prevents a v1 snapshot head and a v2 incremental head from advancing independently. Signed v2 asset-root changes are delegated too; `--skip-assets` is v1-only. A destructive or exposure-changing v2 operation can stop with `BULK_PREVIEW_REQUIRED`; inspect its count-only impact receipt and repeat the same command with `--confirm-bulk <id>:<digest>`. The receipt cannot approve changed files, a new head, another principal, or changed permissions.

For v1, `clone` verifies the hosted pack and every declared asset, installs the complete store through a private stage into a fresh directory, then records `.sevra-sync.json`: the brain identity, feed sequence and hash, pack SHA-256, and per-path digests. V1 `pull` checks local path digests before its first request and `pull --force` explicitly discards local work. V2 never uses this force path or baseline; dbmd owns its private verification state.

For v1, `push` replaces the brain's whole hosted store with the pushed directory and `--force` can approve a shrink or stale-baseline replacement. V2 translates absence into a delete only against dbmd's exact private baseline and requires the path-level delete permission. Before either protocol uploads, the store is checked locally and scanned for secret-shaped markdown, asset bytes, and names. `delete` remains a separate permanent brain-level operation: interactive runs ask for the brain's slug, scripts pass `--confirm <slug>`.

A `.sevralocal` file at the store root keeps files home: one store-relative path or glob per line (`#` comments, blank lines skipped; matched byte-wise and case-sensitively against the pushed paths). Matching files are part of the brain but never part of the cargo — push leaves them on the machine and reports how many stayed home, and while the list has entries every derived `index.md` catalog stays home too (catalogs carry every file's name and summary, kept-home ones included; the hub rebuilds its own). The list itself never uploads. Before upload, `dbmd emit` identifies wiki-links from riding content to any file the canonical push scope keeps home, including derived catalogs. Push declares only those already-exposed target paths so the hub can label the missing edges withheld instead of broken; for every other kept-home file it sends only a count, never its name. A possible linked declaration refuses before the network if dbmd cannot compute it. `DB.md` and `assets.jsonl` always ride: a list that covers either (including via a broad glob like `**`) is refused.

`secrets scan [dir]` runs push's secret scan read-only (exit 1 on matches, 0 clean; matched values never shown). `secrets adopt [dir]` is the first exit: it creates every distinct vault item before changing local content, replaces markdown literals with inert `$NAME` references plus `redacted:` provenance, and turns a secret-bearing UTF-8 text asset into a new portable sanitized derivative. The exact original asset is never rewritten and remains covered by `.sevralocal`; an append-only source wrapper links the derivative back to the original evidence. Binary, non-UTF-8, oversized, and secret-bearing filename cases remain deliberate quarantine/edit work. A private restart journal keyed by value hash makes every phase idempotent after interruption.

For first-time migration, create the brain before its first upload and pass the returned id to adoption: `sevra create <slug> --json`, then `sevra secrets adopt <dir> --brain <id>`, then `sevra push <dir> --brain <id>`. Existing clones infer the destination from their private checkout marker. This ordering makes the first hosted state clean while preserving the exact local evidence.

On an established v2 brain, adoption reports `existingHostingReviewPaths`. Making an original local-only prevents future upload but deliberately does not imply deletion. If its signed current disposition is still hosted, the next push must name the exact path with `--withdraw-from-hosting` and a company audit `--withdraw-reason`; an already-withheld original needs no withdrawal. Neither action erases immutable history or decides whether an issuer-side response is warranted.

`secrets quarantine [dir]` is for a file that is itself secret or an asset that cannot be redacted. It appends each hit file's exact path to `.sevralocal`, creating it when absent. `--dry-run` previews; `--closure` also marks every file connected to a marked one through wiki-links (computed via `dbmd emit`). Kept-home is forward-only: marking changes future snapshots and erases nothing by itself. Retained packs keep bytes that already rode; a kept-home asset remains declared so its blob is not swept; retention-locked backups persist for about 31 days. Rotate at the issuer immediately. Byte erasure requires `sevra delete`, completion of the sweep and backup-retention window, then a fresh push.

The brain vault keeps credentials with the brain, so an agent can retrieve them after moving to another machine. `secrets set` reads up to 256 KiB from stdin only, never from an argument. A hidden terminal prompt accepts text; a pipe accepts arbitrary bytes and trims exactly one final LF or CRLF. `secrets get` writes the exact bytes when stdout is piped. It refuses to reveal a value on a terminal unless `--reveal` is explicit; `--json` returns canonical base64 instead. Names match `^[A-Za-z][A-Za-z0-9_-]{0,63}$`. Browser sessions can manage names and values but cannot retrieve stored values.

`export` always records the brain's vault names in `.sevra-vault.json` inside the exported directory. Values are absent by default. `--with-secrets` explicitly includes recoverable canonical-base64 values and prints a warning; the resulting 0600 file is as sensitive as the credentials themselves. The dot-prefixed file never rides a later push.

`mcp` serves focused brain tools (list_brains, search_brain, get_record, graph, list_runs, start_run) to any MCP client over stdio, including agents that cannot issue separate CLI commands. `list_runs` discovers exact agent names, schedules, configuration flags, the automatic/manual policy, and recent outcomes. `start_run` queues one immediate Sevra-run agent alongside any configured automatic schedule and can spend the owner's run credits. Configure the client with `{"command": "sevra", "args": ["mcp"]}`. It uses the stored sign-in (env `SEVRA_API_KEY` / `SEVRA_HUB_URL` override it); without one, public reads remain available but run controls are unauthorized. stdout carries only JSON-RPC frames; notices go to stderr.

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
