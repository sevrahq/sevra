//! sevra — the command line for the Sevra hub (the managed home for db.md
//! brains). A signed, self-updating, zero-runtime static binary. The Rust port
//! of the original TS single-file CLI; same contract, no Node dependency.
//!
//! anything that is part of the open standards (db.md format operations, the
//! link.md verbs) belongs in `dbmd`; this is the Sevra-specific product
//! surface (login / brains / push / query / grant / publish). `validate`
//! shells the public `dbmd` binary and never links its library.

mod assets;
mod commands;
mod config;
mod hub;
mod local;
mod mcp;
mod output;
mod package;
mod safe_path;
mod scan;
mod signing;
mod store;
mod update;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

use output::{set_json_mode, usage_fail};

#[derive(Parser)]
#[command(
    name = "sevra",
    version,
    about = "The command line for the Sevra hub — the managed home for db.md brains.",
    long_about = None,
)]
struct Cli {
    /// Machine-readable JSON output on stdout for any command (agent-friendly).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Internal installer boundary. Copies the already-verified executable
    /// bytes from stdin through a held, no-follow install-directory handle.
    #[command(name = "__install-verified", hide = true)]
    InstallVerified {
        #[arg(long)]
        dir: String,
        #[arg(long)]
        sha256: String,
    },
    /// Sign in: approve in the browser (default), or --key to store a key.
    /// Stored at ~/.sevra/config.json. With --json, sign-in first emits one
    /// compact awaiting_approval line (relay its URL, and its code when there
    /// is one), then the final login object.
    Login {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        hub: Option<String>,
        /// Skip the browser and use a sign-in code (SSH, headless, or when
        /// approving from another computer).
        #[arg(long)]
        no_browser: bool,
    },
    /// Remove the stored credential
    Logout,
    /// Show the signed-in account
    Whoami,
    /// List your brains
    Brains,
    /// Show a brain's configured run agents and schedule state
    Agents { brain: String },
    /// Show a brain's recent run history
    Runs { brain: String },
    /// Manually queue one Sevra-run agent
    Run { brain: String, agent: String },
    /// Create a brain
    Create {
        slug: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        public: bool,
    },
    /// Permanently delete a brain and everything the hub holds for it
    /// (owner-only). Interactive runs show what dies and ask for the brain's
    /// slug; scripts and agents pass --confirm <slug>. There is no undo.
    Delete {
        brain: String,
        /// The brain's exact slug — confirms without the interactive prompt
        #[arg(long, value_name = "SLUG")]
        confirm: Option<String>,
    },
    /// Sync local changes to a brain. Link.md v2 delegates to dbmd's verified
    /// incremental engine: only changed blobs and explicit deletes travel,
    /// conflicts never overwrite, and --force is refused. Legacy v1 brains
    /// retain whole-store replacement until an explicit verified bridge.
    /// Before anything uploads, the store is checked and scanned for
    /// secret-shaped markdown, asset contents, and names (--allow-secrets
    /// overrides). Bounded asset inspection reports anything it skips.
    ///
    /// A `.sevralocal` file at the store root keeps files home: one
    /// store-relative path or glob per line (`#` comments). Matching files
    /// are part of the brain but never part of the cargo — they stay on this
    /// machine, and the list itself never uploads either. While the list has
    /// entries, derived index.md catalogs stay home too (the hub rebuilds
    /// its own). `sevra secrets quarantine` maintains the list.
    Push {
        dir: String,
        #[arg(long)]
        brain: String,
        /// Legacy v1 only: allow a shrinking or stale-baseline replacement
        #[arg(long)]
        force: bool,
        /// Push even when the secret scan finds matches
        #[arg(long)]
        allow_secrets: bool,
        /// Skip the post-commit asset byte sync (`assets.jsonl`-declared
        /// blobs the hub reports missing upload by default). Legacy v1 only;
        /// v2 commits its signed asset root through dbmd.
        #[arg(long)]
        skip_assets: bool,
        /// Approve paths newly made eligible by a `.sevralocal` change. On v2
        /// this delegates to dbmd's exact local-policy transition guard.
        #[arg(long)]
        resume_local_policy: bool,
        /// Confirm the exact permissioned bulk preview from the preceding v2
        /// attempt. Changing the principal, head, permissions, or files makes
        /// the receipt invalid.
        #[arg(long, value_name = "ID:DIGEST")]
        confirm_bulk: Option<String>,
        /// Remove one exact currently hosted path while preserving the local
        /// kept-home file. Repeatable; requires --withdraw-reason.
        #[arg(
            long,
            value_name = "PATH",
            action = clap::ArgAction::Append,
            requires = "withdraw_reason"
        )]
        withdraw_from_hosting: Vec<String>,
        /// Bounded company audit reason for this exact withdrawal batch.
        #[arg(long, value_name = "REASON", requires = "withdraw_from_hosting")]
        withdraw_reason: Option<String>,
    },
    /// Rebind one reused mutable brain alias after reviewing both canonical ids.
    /// Both trust histories remain pinned; this never deletes local state.
    Rebind {
        brain: String,
        #[arg(long, value_name = "OLD_BRAIN_ULID")]
        from: String,
        #[arg(long, value_name = "NEW_BRAIN_ULID")]
        to: String,
    },
    /// Bring a hosted brain onto this machine for the first time. Link.md v2
    /// delegates verification, scoped materialization, and private baselines
    /// to dbmd; the checkout lands atomically in a fresh directory.
    Clone { brain: String, dir: Option<String> },
    /// Refresh a cloned brain in place. V2 performs a verified three-way sync
    /// and preserves conflicts; --force applies only to legacy v1 snapshots.
    Pull {
        dir: Option<String>,
        /// Legacy v1 only: discard local divergence and replace riding paths
        #[arg(long)]
        force: bool,
    },
    /// Inspect private Link.md v2 conflict bundles for a local brain checkout.
    Conflicts {
        /// db.md store containing `.dbmd/conflicts/`
        dir: Option<String>,
        /// Remove expired and interrupted bundles
        #[arg(long)]
        prune: bool,
        /// Also remove completed unexpired bundles; requires --prune
        #[arg(long, requires = "prune")]
        all: bool,
    },
    /// Resolve one exact Link.md v2 conflict bundle through Sevra's stored
    /// login. Exactly one resolution choice is required; this never acts as force.
    Resolve {
        bundle: String,
        /// db.md store containing the private conflict bundle
        #[arg(long, default_value = ".")]
        dir: String,
        #[arg(long, conflicts_with_all = ["take_remote", "from_file"])]
        keep_local: bool,
        #[arg(long, conflicts_with_all = ["keep_local", "from_file"])]
        take_remote: bool,
        /// Bounded, no-follow UTF-8 merged candidate; only for a one-path bundle
        #[arg(long = "from", value_name = "SAFE_FILE", conflicts_with_all = ["keep_local", "take_remote"])]
        from_file: Option<String>,
        #[arg(long, value_name = "ID:DIGEST")]
        confirm_bulk: Option<String>,
    },
    /// Query a brain by text + frontmatter filters
    Query {
        /// The brain (with --brain given, this positional is the search text)
        #[arg(value_name = "BRAIN")]
        brain: Option<String>,
        /// Free-text search
        #[arg(value_name = "TEXT")]
        text: Option<String>,
        /// The brain to query — an alias of the first positional (the same
        /// flag `push` uses)
        #[arg(long = "brain", value_name = "BRAIN")]
        brain_flag: Option<String>,
        #[arg(long = "type")]
        type_: Option<String>,
        #[arg(long)]
        layer: Option<String>,
        #[arg(long = "meta-type")]
        meta_type: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        order: Option<String>,
        /// Max results (the hub clamps to 1..200)
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        r#where: Option<String>,
    },
    /// Fetch one record by db.md id or path
    Get { brain: String, reference: String },
    /// Inspect the wiki-link graph around a record
    Graph {
        brain: String,
        path: String,
        /// Edge direction (default: both)
        #[arg(long, value_parser = ["in", "out", "both"])]
        dir: Option<String>,
    },
    /// Serve your brains and manual run controls to MCP clients over stdio
    Mcp,
    /// Grant a person read (or --write) access
    Grant {
        brain: String,
        email: String,
        #[arg(long)]
        write: bool,
    },
    /// List a brain's grants
    Grants { brain: String },
    /// Revoke a grant by id
    Revoke { brain: String, grant_id: String },
    /// Brains shared with you
    Shared,
    /// Render public records to <handle>.sevra.page
    Publish { brain: String },
    /// Pull all public pages
    Unpublish { brain: String },
    /// The brain vault: values stay server-side and follow you across machines
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },
    /// Read the evidence inbox (drain = full JSON)
    Inbox {
        #[arg(value_parser = ["list", "drain"])]
        action: String,
        brain: String,
    },
    /// Write your brain back to disk (you own it)
    Export {
        brain: String,
        dir: Option<String>,
        /// Skip restoring `assets.jsonl`-declared blobs beside the store
        #[arg(long)]
        skip_assets: bool,
        /// Include vault values in the private `.sevra-vault.json` export file
        #[arg(long)]
        with_secrets: bool,
    },
    /// Checkpoint, pull, verify, or restore a dependency-aware brain package. The db.md
    /// store remains the semantic core; governed companion files ride the
    /// existing content-addressed asset lane and restore to their runtime paths.
    Package {
        #[command(subcommand)]
        action: PackageAction,
    },
    /// Validate a store (wraps `dbmd validate --all`)
    Validate { dir: Option<String> },
    /// Print this build's version
    Version,
    /// Update to the hub's current release (signed; checks dbmd too)
    Update,
}

fn install_verified(dir: &str, expected_sha256: &str) -> Result<(), String> {
    const MAX_INSTALL_BYTES: u64 = 128 * 1024 * 1024;

    if expected_sha256.len() != 64
        || expected_sha256
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err("expected SHA-256 is not canonical lowercase hex".to_string());
    }
    let dir = Path::new(dir);
    if !dir.is_absolute() {
        return Err("install directory must be absolute".to_string());
    }

    safe_path::ensure_dir(dir, 0o755)
        .map_err(|error| format!("could not securely create install directory: {error}"))?;
    let held = safe_path::SafeDir::open(dir)
        .map_err(|error| format!("could not securely hold install directory: {error}"))?;
    let stdin = std::io::stdin();
    let mut source = stdin.lock();
    held.atomic_write_with("sevra", false, 0o755, |staged| {
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| std::io::Error::other("installer input length overflow"))?;
            if total > MAX_INSTALL_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "verified installer input exceeds the size limit",
                ));
            }
            hasher.update(&buffer[..read]);
            staged.write_all(&buffer[..read])?;
        }
        if format!("{:x}", hasher.finalize()) != expected_sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "verified installer input changed after verification",
            ));
        }
        Ok(())
    })
    .map_err(|error| format!("could not atomically install verified executable: {error}"))
}

#[derive(Subcommand)]
enum SecretsAction {
    /// List vault item names (never values)
    List { brain: String },
    /// Show declared, provisioned, and used secret names (never values)
    Status { brain: String },
    /// Store or rotate one vault item. The VALUE is read from stdin — hidden
    /// prompt on a TTY, piped otherwise (one trailing newline trimmed) —
    /// never from the command line, never echoed.
    Set {
        brain: String,
        /// 1-64 letters, numbers, underscores, or hyphens; starts with a letter
        #[arg(value_parser = commands::parse_secret_name)]
        name: String,
        // Traps, hidden from help: anything value-shaped in argv is refused
        // WITHOUT being echoed (clap's own unexpected-argument error would
        // print it — see commands::secrets_set).
        #[arg(long, hide = true)]
        value: Option<String>,
        #[arg(hide = true, value_name = "REFUSED", num_args = 0..)]
        value_argv: Vec<String>,
    },
    /// Retrieve one value (pipe-safe; a terminal requires --reveal)
    Get {
        brain: String,
        /// The vault item's name
        #[arg(value_parser = commands::parse_secret_name)]
        name: String,
        /// Reveal a value when stdout is a terminal
        #[arg(long)]
        reveal: bool,
    },
    /// Delete one vault item
    #[command(name = "rm", visible_alias = "delete")]
    Rm {
        brain: String,
        /// The vault item's name
        #[arg(value_parser = commands::parse_secret_name)]
        name: String,
    },
    /// Scan a local store for secret-shaped markdown, asset contents, and
    /// names — the same bounded scan `push` runs, read-only and offline. Exit
    /// 1 on matches, 0 when clean; matched values are never shown. Honors
    /// `.sevralocal` (kept-home files never ride, so they are not scanned).
    Scan { dir: Option<String> },
    /// Keep secret-bearing files home: scan the full store and append each
    /// hit file's exact path to `.sevralocal` (created if absent), so the
    /// NEXT push leaves those files on this machine. Forward-only: retained
    /// packs and backups preserve bytes that already rode; marking erases
    /// nothing. DB.md and assets.jsonl are never marked — they ride every
    /// push, so a secret inside them is an edit case.
    Quarantine {
        dir: Option<String>,
        /// Show what would be marked; write nothing
        #[arg(long)]
        dry_run: bool,
        /// Also mark every file connected to a marked one through
        /// wiki-links (undirected), computed via `dbmd emit`
        #[arg(long)]
        closure: bool,
    },
    /// Move detected credentials into the brain vault. Markdown literals become
    /// inert `$NAME` references; text assets gain portable sanitized derivatives
    /// while their exact originals remain local-only.
    Adopt {
        dir: Option<String>,
        /// Explicit vault destination for pre-upload onboarding. Must match any
        /// existing checkout marker.
        #[arg(long, value_name = "BRAIN")]
        brain: Option<String>,
    },
}

#[derive(Subcommand)]
enum PackageAction {
    /// Snapshot one closure profile and push it atomically with the brain.
    Checkpoint {
        /// Workspace containing its brain at `db/`
        workspace: String,
        #[arg(long)]
        brain: String,
        #[arg(long, default_value = "working")]
        profile: String,
        /// Preserve the existing push override for secret-shaped brain text.
        /// Companion content remains independently scanned and cannot bypass
        /// its package policy with this flag.
        #[arg(long)]
        allow_secrets: bool,
        #[arg(long, value_name = "ID:DIGEST")]
        confirm_bulk: Option<String>,
    },
    /// Clone a v2 brain into `<workspace>/db`, restore its packaged companion
    /// files around it, and emit an honest closure report.
    Restore {
        brain: String,
        workspace: String,
        #[arg(long, default_value = "working")]
        profile: String,
    },
    /// Incrementally pull the brain and reconcile clean companion changes.
    /// A receipt-less Git clone is adopted only after its hosted brain and
    /// signed companion snapshot verify exactly.
    Pull {
        /// Existing package workspace containing its brain at `db/`
        workspace: String,
        #[arg(long, default_value = "working")]
        profile: String,
    },
    /// Verify package objects, restored paths, dependencies, and snapshot root.
    Verify {
        workspace: String,
        #[arg(long, default_value = "working")]
        profile: String,
    },
}

fn main() {
    // Sweep any `<exe>.old.<pid>` leftover a previous Windows self-swap
    // parked (the old exe stays delete-locked until its process exits, so
    // the swap defers cleanup to here). No-op on unix.
    update::cleanup_stale_swaps();
    // Even clap's own output honors the --json contract: an agent parsing
    // stdout must get a JSON object, never human text — including the
    // built-in `--version`/`--help` flags. Exit codes stay clap's
    // (0 = help/version, 2 = usage error).
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        if std::env::args().any(|a| a == "--json") {
            use clap::error::ErrorKind;
            match e.kind() {
                ErrorKind::DisplayVersion => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "version": update::VERSION,
                            "target": update::asset_target(),
                        })
                    );
                    std::process::exit(0);
                }
                ErrorKind::DisplayHelp => {
                    println!("{}", serde_json::json!({ "help": e.render().to_string() }));
                    std::process::exit(0);
                }
                _ if e.use_stderr() => {
                    println!(
                        "{}",
                        serde_json::json!({ "error": e.render().to_string().trim() })
                    );
                    std::process::exit(2);
                }
                _ => {}
            }
        }
        let raw = e.render().to_string();
        let rendered = if matches!(
            e.kind(),
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
        ) {
            crate::output::terminal_layout_safe(&raw)
        } else {
            crate::output::terminal_safe(&raw)
        };
        if e.use_stderr() {
            eprint!("{rendered}");
        } else {
            print!("{rendered}");
        }
        std::process::exit(e.exit_code());
    });
    set_json_mode(cli.json);

    // Commands that don't need a loaded credential first.
    match &cli.command {
        Commands::InstallVerified { dir, sha256 } => {
            if let Err(error) = install_verified(dir, sha256) {
                eprintln!("sevra install helper: {error}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Login {
            key,
            hub,
            no_browser,
        } => return commands::login(hub.clone(), key.clone(), *no_browser),
        Commands::Logout => return commands::logout(),
        Commands::Package {
            action: PackageAction::Verify { workspace, profile },
        } => return package::verify_command(workspace.clone(), profile.clone()),
        Commands::Conflicts { dir, prune, all } => {
            return commands::sync_conflicts(dir.clone(), *prune, *all)
        }
        Commands::Validate { dir } => return commands::validate(dir.clone()),
        Commands::Version => return update::cmd_version(),
        _ => {}
    }

    let cfg = config::load();
    match cli.command {
        Commands::Whoami => commands::whoami(&cfg),
        Commands::Brains => commands::brains(&cfg),
        Commands::Agents { brain } => commands::agents(&cfg, &brain),
        Commands::Runs { brain } => commands::runs(&cfg, &brain),
        Commands::Run { brain, agent } => commands::run(&cfg, &brain, &agent),
        Commands::Create {
            slug,
            name,
            scope,
            public,
        } => commands::create(&cfg, &slug, name, scope, public),
        Commands::Delete { brain, confirm } => commands::delete(&cfg, &brain, confirm),
        Commands::Push {
            dir,
            brain,
            force,
            allow_secrets,
            skip_assets,
            resume_local_policy,
            confirm_bulk,
            withdraw_from_hosting,
            withdraw_reason,
        } => commands::push(
            &cfg,
            &dir,
            &brain,
            commands::PushOptions {
                force,
                allow_secrets,
                skip_assets,
                resume_local_policy,
                confirm_bulk: confirm_bulk.as_deref(),
                withdraw_from_hosting: &withdraw_from_hosting,
                withdraw_reason: withdraw_reason.as_deref(),
                package_report: None,
            },
        ),
        Commands::Rebind { brain, from, to } => commands::rebind_brain(&cfg, &brain, &from, &to),
        Commands::Clone { brain, dir } => commands::clone_brain(&cfg, &brain, dir),
        Commands::Pull { dir, force } => commands::pull(&cfg, dir, force),
        Commands::Resolve {
            bundle,
            dir,
            keep_local,
            take_remote,
            from_file,
            confirm_bulk,
        } => {
            if usize::from(keep_local) + usize::from(take_remote) + usize::from(from_file.is_some())
                != 1
            {
                usage_fail("resolve requires exactly one of --keep-local, --take-remote, or --from <safe-file>");
            }
            commands::sync_resolve(
                &cfg,
                &bundle,
                &dir,
                keep_local,
                take_remote,
                from_file.as_deref(),
                confirm_bulk.as_deref(),
            )
        }
        Commands::Query {
            brain,
            text,
            brain_flag,
            type_,
            layer,
            meta_type,
            tag,
            order,
            limit,
            r#where,
        } => {
            let (brain, text) = match commands::resolve_query_target(brain_flag, brain, text) {
                Ok(target) => target,
                Err(msg) => usage_fail(&msg),
            };
            commands::query(
                &cfg, &brain, text, type_, layer, meta_type, tag, order, limit, r#where,
            )
        }
        Commands::Get { brain, reference } => commands::get(&cfg, &brain, &reference),
        Commands::Graph { brain, path, dir } => commands::graph(&cfg, &brain, &path, dir),
        Commands::Mcp => mcp::serve(&cfg),
        Commands::Grant {
            brain,
            email,
            write,
        } => commands::grant(&cfg, &brain, &email, write),
        Commands::Grants { brain } => commands::grants(&cfg, &brain),
        Commands::Revoke { brain, grant_id } => commands::revoke(&cfg, &brain, &grant_id),
        Commands::Shared => commands::shared(&cfg),
        Commands::Publish { brain } => commands::publish(&cfg, &brain),
        Commands::Unpublish { brain } => commands::unpublish(&cfg, &brain),
        Commands::Secrets { action } => match action {
            SecretsAction::List { brain } => commands::secrets_list(&cfg, &brain),
            SecretsAction::Status { brain } => commands::secrets_status(&cfg, &brain),
            SecretsAction::Set {
                brain,
                name,
                value,
                value_argv,
            } => {
                let value_in_argv = value.is_some() || !value_argv.is_empty();
                commands::secrets_set(&cfg, &brain, &name, value_in_argv)
            }
            SecretsAction::Get {
                brain,
                name,
                reveal,
            } => commands::secrets_get(&cfg, &brain, &name, reveal),
            SecretsAction::Rm { brain, name } => commands::secrets_delete(&cfg, &brain, &name),
            // Scan/quarantine are local-only. Adopt is vault-backed and
            // enforces login before it reads the store.
            SecretsAction::Scan { dir } => commands::secrets_scan(dir),
            SecretsAction::Quarantine {
                dir,
                dry_run,
                closure,
            } => commands::secrets_quarantine(dir, dry_run, closure),
            SecretsAction::Adopt { dir, brain } => commands::secrets_adopt(&cfg, dir, brain),
        },
        Commands::Inbox { action, brain } => commands::inbox(&cfg, &action, &brain),
        Commands::Export {
            brain,
            dir,
            skip_assets,
            with_secrets,
        } => commands::export(&cfg, &brain, dir, skip_assets, with_secrets),
        Commands::Package { action } => match action {
            PackageAction::Checkpoint {
                workspace,
                brain,
                profile,
                allow_secrets,
                confirm_bulk,
            } => package::checkpoint_command(
                &cfg,
                workspace,
                brain,
                profile,
                allow_secrets,
                confirm_bulk,
            ),
            PackageAction::Restore {
                brain,
                workspace,
                profile,
            } => package::restore_command(&cfg, brain, workspace, profile),
            PackageAction::Pull { workspace, profile } => {
                package::pull_command(&cfg, workspace, profile)
            }
            PackageAction::Verify { .. } => unreachable!(),
        },
        Commands::Update => update::cmd_update(&cfg),
        // handled above
        Commands::Login { .. }
        | Commands::InstallVerified { .. }
        | Commands::Logout
        | Commands::Conflicts { .. }
        | Commands::Validate { .. }
        | Commands::Version => unreachable!(),
    }

    // The daily auto-update, AFTER the command's output — its download can
    // never add latency to the answer an agent is waiting on.
    update::run_deferred_auto_update();
}
