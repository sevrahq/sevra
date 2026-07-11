//! sevra — the command line for the Sevra hub (the managed home for db.md
//! brains). A signed, self-updating, zero-runtime static binary. The Rust port
//! of the original TS single-file CLI; same contract, no Node dependency.
//!
//! anything that is part of the open standards (db.md format operations, the
//! link.md verbs) belongs in `dbmd`; this is the Sevra-specific product
//! surface (login / brains / push / query / grant / publish). `validate`
//! shells the public `dbmd` binary and never links its library.

mod commands;
mod config;
mod hub;
mod output;
mod signing;
mod store;
mod update;

use clap::{Parser, Subcommand};

use output::set_json_mode;

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
    /// Store your hub credential (~/.sevra/config.json)
    Login {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        hub: Option<String>,
    },
    /// Remove the stored credential
    Logout,
    /// Show the signed-in account
    Whoami,
    /// List your brains
    Brains,
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
    /// Push a local db.md store (index-on-push)
    Push {
        dir: String,
        #[arg(long)]
        brain: String,
    },
    /// Query a brain by text + frontmatter filters
    Query {
        brain: String,
        text: Option<String>,
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
    /// Read the evidence inbox (drain = full JSON)
    Inbox {
        #[arg(value_parser = ["list", "drain"])]
        action: String,
        brain: String,
    },
    /// Write your brain back to disk (you own it)
    Export { brain: String, dir: Option<String> },
    /// Validate a store (wraps `dbmd validate --all`)
    Validate { dir: Option<String> },
    /// Print this build's version
    Version,
    /// Update to the hub's current release (signed; checks dbmd too)
    Update,
}

fn main() {
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
        e.exit();
    });
    set_json_mode(cli.json);

    // Commands that don't need a loaded credential first.
    match &cli.command {
        Commands::Login { key, hub } => return commands::login(hub.clone(), key.clone()),
        Commands::Logout => return commands::logout(),
        Commands::Validate { dir } => return commands::validate(dir.clone()),
        Commands::Version => return update::cmd_version(),
        _ => {}
    }

    let cfg = config::load();
    match cli.command {
        Commands::Whoami => commands::whoami(&cfg),
        Commands::Brains => commands::brains(&cfg),
        Commands::Create {
            slug,
            name,
            scope,
            public,
        } => commands::create(&cfg, &slug, name, scope, public),
        Commands::Push { dir, brain } => commands::push(&cfg, &dir, &brain),
        Commands::Query {
            brain,
            text,
            type_,
            layer,
            meta_type,
            tag,
            order,
            limit,
            r#where,
        } => commands::query(
            &cfg, &brain, text, type_, layer, meta_type, tag, order, limit, r#where,
        ),
        Commands::Get { brain, reference } => commands::get(&cfg, &brain, &reference),
        Commands::Graph { brain, path, dir } => commands::graph(&cfg, &brain, &path, dir),
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
        Commands::Inbox { action, brain } => commands::inbox(&cfg, &action, &brain),
        Commands::Export { brain, dir } => commands::export(&cfg, &brain, dir),
        Commands::Update => update::cmd_update(&cfg),
        // handled above
        Commands::Login { .. }
        | Commands::Logout
        | Commands::Validate { .. }
        | Commands::Version => unreachable!(),
    }

    // The daily auto-update, AFTER the command's output — its download can
    // never add latency to the answer an agent is waiting on.
    update::run_deferred_auto_update();
}
