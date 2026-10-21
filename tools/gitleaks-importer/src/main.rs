//! gitleaks-importer: load a gitleaks TOML config into the SQLite rule database.
//!
//!   gitleaks-importer --db rules.db import third_party/gitleaks/config/gitleaks.toml \
//!        --source-version v8.30 --commit b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b
//!   gitleaks-importer --db rules.db versions
//!   gitleaks-importer --db rules.db rollback 3        # then POST /v1/rules/reload (or dlp_reload_rules)
//!   gitleaks-importer --db rules.db history           # past imports with counts
use clap::{Parser, Subcommand};
use dlp_storage::gitleaks::{import_gitleaks_toml, ImportMeta};
use dlp_storage::Store;

#[derive(Parser)]
#[command(name = "gitleaks-importer", version)]
struct Cli {
    #[arg(long, default_value = "ai_dlp.db")]
    db: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// import / update rules (idempotent; unsupported rules are stored disabled with the reason)
    Import {
        file: String,
        #[arg(long, default_value = "")]
        source_version: String,
        #[arg(long, default_value = "")]
        commit: String,
        /// print the full JSON report (incompatible rules, counts)
        #[arg(long)]
        json: bool,
    },
    Versions,
    /// restore the rule tables to a snapshot; run a rule reload afterwards
    Rollback { version: i64 },
    History,
}

fn die<T>(e: impl std::fmt::Display) -> T {
    eprintln!("error: {e}");
    std::process::exit(1)
}

fn main() {
    let cli = Cli::parse();
    let store = Store::open(&cli.db).unwrap_or_else(die);
    match cli.cmd {
        Cmd::Import { file, source_version, commit, json } => {
            let text = std::fs::read_to_string(&file).unwrap_or_else(die);
            let r = import_gitleaks_toml(&store, &text, &ImportMeta { source_version, source_commit: commit }).unwrap_or_else(die);
            if json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else {
                println!("total={} inserted={} updated={} unchanged={} skipped_locked={} unsupported={} path_only={} translated={} global_allowlists={}", r.total, r.inserted, r.updated, r.unchanged, r.skipped_locked, r.unsupported, r.path_only, r.translated, r.global_allowlists);
                for (id, why) in &r.incompatible {
                    println!("  INCOMPATIBLE {id}: {why}");
                }
                for (id, why) in &r.compile_failures {
                    println!("  COMPILE-FAIL {id}: {why}");
                }
                println!("snapshot before import: v{:?}, after: v{:?} (rollback with `rollback <version>`)", r.version_before, r.version_after);
            }
        }
        Cmd::Versions => {
            for v in store.list_versions().unwrap_or_else(die) {
                println!("v{:<4} {} {} {}", v.version, if v.active { "*" } else { " " }, v.created_at, v.reason);
            }
        }
        Cmd::Rollback { version } => {
            store.restore_version(version).unwrap_or_else(die);
            println!("tables restored to snapshot v{version}; reload the engine to activate (POST /v1/rules/reload)");
        }
        Cmd::History => {
            let d = store.list_versions().unwrap_or_else(die);
            println!("{} snapshots; see table rule_imports for per-import reports", d.len());
        }
    }
}
