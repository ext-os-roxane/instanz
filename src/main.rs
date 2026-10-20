//! `instanz` — ExtOS hypervisor and runlevel engine.
//!
//! The binary is a synchronous CLI. The apply pipeline calls
//! `libextos::ingest`, which is built on `reqwest::blocking`; installing a Tokio
//! runtime here would panic with "Cannot drop a runtime in a context where
//! blocking is not allowed", so there is deliberately no async runtime.
//!
//! Wired in Phase 2.5: `evaluate`, `apply`, `rollback`, `gc`, `generations`.
//! `run`, `shell` and the raw `snapshot` verbs stay explicit `todo!()`s until
//! their phases (container runtime, DevShells, snapshot UX) land.

mod orchestrate;
mod system;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use clap::{Parser, Subcommand};

use crate::orchestrate::{
    ApplyOptions, RollbackTarget, apply, evaluate, gc, generations, open_repo, parse_hash_algo,
    print_evaluation, print_generations, rollback,
};
use crate::system::SystemConfig;

/// instanz — ExtOS Hypervisor & Runlevel Engine
///
/// Manages system snapshots, executes the Symlink/Reflink Weaver,
/// provisions containers (Levels 0-4), and orchestrates the
/// declarative boot lifecycle.
#[derive(Parser)]
#[command(name = "instanz", version, about, long_about = None)]
struct Cli {
    /// Path to the CAS repository root
    #[arg(long, default_value = "/repository", env = "EXTOS_REPOSITORY", global = true)]
    repository: PathBuf,

    /// Hash algorithm for CAS objects
    #[arg(long, default_value = "blake3", global = true)]
    hash_algo: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate a system.nix without applying changes (dry-run DAG check)
    Evaluate {
        /// Path to the system configuration file
        config: String,
    },
    /// Apply a system configuration: fetch → snapshot → weave → phantom → tools
    Apply {
        /// Path to the system configuration file
        #[arg(default_value = crate::system::DEFAULT_CONFIG_PATH)]
        config: String,
        /// Generations root (default: `EXTOS_ROOTFS`, else the config's `root`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
    },
    /// Rollback to a previous generation
    Rollback {
        /// Generation number or `prev` (default: previous)
        #[arg(long)]
        generation: Option<String>,
        /// Generations root (default: `EXTOS_ROOTFS`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
    },
    /// Spawn a Tier 4 container interactively
    Run {
        /// Container profile name (e.g., "android-subsystem", "firefox-sandboxed")
        profile: String,
    },
    /// Enter an ephemeral DevShell (Level 1 container from dev.nix)
    Shell {
        /// Path to dev.nix (default: ./dev.nix)
        #[arg(default_value = "./dev.nix")]
        config: String,
    },
    /// Manage Btrfs snapshots
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// Garbage collect old generations and snapshots
    Gc {
        /// Number of generations to keep
        #[arg(long = "keep", alias = "keep-generations", default_value = "3")]
        keep_generations: u32,
        /// Generations root (default: `EXTOS_ROOTFS`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
    },
    /// List all generations and their status
    Generations {
        /// Generations root (default: `EXTOS_ROOTFS`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SnapshotAction {
    /// List all snapshots
    List,
    /// Create a new snapshot of the current system
    Create {
        /// Snapshot name
        name: String,
    },
    /// Delete a snapshot
    Delete {
        /// Snapshot name
        name: String,
    },
}

/// BLS entries directory, when the operator mapped one (`EXTOS_BLS_DIR`).
///
/// Production mapping: `EXTOS_BLS_DIR=/boot/loader/entries`. Unset means
/// symlink-only mode — generations still switch, no bootloader entry is written.
fn bls_dir() -> Option<PathBuf> {
    std::env::var_os("EXTOS_BLS_DIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Rootfs for `apply`: CLI/env flag first, then the config's `root` key.
fn rootfs_from_config(flag: Option<PathBuf>, config: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path);
    }
    if let Some(path) = config {
        return Ok(path);
    }
    bail!(
        "no generations root configured: pass --rootfs, set EXTOS_ROOTFS, \
         or add `root = \"/runlevel/1/<system>\";` to the system config"
    )
}

/// Rootfs for commands that have no config to fall back on.
fn require_rootfs(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    flag.ok_or_else(|| {
        anyhow!("no generations root configured: pass --rootfs or set EXTOS_ROOTFS")
    })
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let algo = parse_hash_algo(&cli.hash_algo);

    match cli.command {
        Commands::Evaluate { config } => {
            let system = SystemConfig::load(Path::new(&config))?;
            let repo = open_repo(&cli.repository, algo)?;
            let evaluation = evaluate(&repo, system)?;
            print_evaluation(&evaluation, &repo);
            Ok(())
        }
        Commands::Apply { config, rootfs } => {
            let system = SystemConfig::load(Path::new(&config))?;
            let rootfs = rootfs_from_config(rootfs, system.root.clone())?;
            let repo = open_repo(&cli.repository, algo)?;
            let cache_dir = repo.root.join("cache");
            let bls = bls_dir();
            let options = ApplyOptions {
                rootfs: &rootfs,
                cache_dir: &cache_dir,
                bls_dir: bls.as_deref(),
            };
            let report = apply(&repo, system, &options)?;
            println!(
                "generation {} → {} ({} op(s), {} phantom row(s), lock {})",
                report.generation,
                report.root.display(),
                report.plan_ops,
                report.phantom_rows,
                report.lockfile.display()
            );
            Ok(())
        }
        Commands::Rollback { generation, rootfs } => {
            let rootfs = require_rootfs(rootfs)?;
            let target = RollbackTarget::parse(generation.as_deref())?;
            let bls = bls_dir();
            rollback(&rootfs, target, bls.as_deref())?;
            Ok(())
        }
        Commands::Run { profile } => {
            tracing::info!("instanz run: {profile}");
            todo!("M10: Container runtime")
        }
        Commands::Shell { config } => {
            tracing::info!("instanz shell: {config}");
            todo!("M16.7: DevShells")
        }
        Commands::Snapshot { action } => match action {
            SnapshotAction::List => {
                tracing::info!("instanz snapshot list");
                todo!("M8.1: Snapshot listing")
            }
            SnapshotAction::Create { name } => {
                tracing::info!("instanz snapshot create: {name}");
                todo!("M8.1: Snapshot creation")
            }
            SnapshotAction::Delete { name } => {
                tracing::info!("instanz snapshot delete: {name}");
                todo!("M8.1: Snapshot deletion")
            }
        },
        Commands::Gc {
            keep_generations,
            rootfs,
        } => {
            let rootfs = require_rootfs(rootfs)?;
            let repo = open_repo(&cli.repository, algo)?;
            let bls = bls_dir();
            let report = gc(
                &repo,
                &rootfs,
                keep_generations as usize,
                bls.as_deref(),
            )?;
            println!(
                "gc: {} generation(s), {} object(s) purged",
                report.generations.len(),
                report.objects.len()
            );
            Ok(())
        }
        Commands::Generations { rootfs } => {
            let rootfs = require_rootfs(rootfs)?;
            let rows = generations(&rootfs)?;
            print_generations(&rootfs, &rows);
            Ok(())
        }
    }
}
