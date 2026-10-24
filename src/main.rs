//! `instanz` — ExtOS hypervisor and runlevel engine.
//!
//! The binary is a synchronous CLI. The apply pipeline calls
//! `libextos::ingest`, which is built on `reqwest::blocking`; installing a Tokio
//! runtime here would panic with "Cannot drop a runtime in a context where
//! blocking is not allowed", so there is deliberately no async runtime.
//!
//! The one sanctioned exception is `instanz serve` (PLAN 8.1.4, `mod rpc`): it
//! builds its own explicit multi-thread Tokio runtime and bridges every
//! blocking domain call through `tokio::task::spawn_blocking`, whose worker
//! threads permit blocking drops — the CLI's sync main is otherwise unchanged.
//!
//! Wired in Phase 2.5: `evaluate`, `apply`, `rollback`, `gc`, `generations`.
//! Phase-4 residual: `apply` now ends with a runlevel-0 forge (initramfs + BLS
//! matrix, PLAN 4.2.6) and an orphan-generation sweep, and `run <profile>`
//! boots a container from the applied generation (PLAN 4.4.8). `shell` and the
//! raw `snapshot` verbs stay explicit `todo!()`s until their phases land.

mod forge;
mod mount;
mod orchestrate;
mod reaper;
mod rpc;
mod run;
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
    /// Apply a system configuration: fetch → snapshot → weave → phantom → tools → forge
    Apply {
        /// Path to the system configuration file
        #[arg(default_value = crate::system::DEFAULT_CONFIG_PATH)]
        config: String,
        /// Generations root (default: `EXTOS_ROOTFS`, else the config's `root`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
        /// Boot root the forge writes the initramfs + BLS matrix into
        /// (see `--bls-dir` for the legacy snapshot-entry mode)
        #[arg(long, env = crate::forge::ENV_BOOT_ROOT)]
        boot_root: Option<PathBuf>,
        /// Legacy BLS entries directory (snapshot `gen-<n>.conf` entries, no forge)
        #[arg(long, env = "EXTOS_BLS_DIR")]
        bls_dir: Option<PathBuf>,
    },
    /// Rollback to a previous generation
    Rollback {
        /// Generation number or `prev` (default: previous)
        #[arg(long)]
        generation: Option<String>,
        /// Generations root (default: `EXTOS_ROOTFS`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
        /// Boot root whose forge entry the loader default should point at
        #[arg(long, env = crate::forge::ENV_BOOT_ROOT)]
        boot_root: Option<PathBuf>,
        /// Legacy BLS entries directory (`gen-<n>.conf` entries)
        #[arg(long, env = "EXTOS_BLS_DIR")]
        bls_dir: Option<PathBuf>,
    },
    /// Spawn a container profile from the applied generation
    Run {
        /// Container profile name (a system name or a package profile)
        profile: String,
        /// Generations root (default: `EXTOS_ROOTFS`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
        /// Isolation level 0 (isolated) … 4 (privileged); overrides the profile
        #[arg(long)]
        level: Option<u8>,
        /// Backend: native, nspawn, runc, crun, chroot
        #[arg(long, env = "EXTOS_CONTAINER_BACKEND")]
        backend: Option<String>,
        /// Program inside the roof (overrides the profile entrypoint)
        #[arg(long)]
        program: Option<String>,
        /// System config used for `containerPermissions` lookup
        #[arg(long, env = crate::run::ENV_SYSTEM_CONFIG)]
        config: Option<PathBuf>,
        /// Explicit opt-in for a level-4 (privileged) launch
        #[arg(long)]
        allow_privileged: bool,
        /// Arguments appended to the container program
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "ARG")]
        args: Vec<String>,
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
        /// Boot root whose forge entries the GC prunes
        #[arg(long, env = crate::forge::ENV_BOOT_ROOT)]
        boot_root: Option<PathBuf>,
        /// Legacy BLS entries directory the GC prunes
        #[arg(long, env = "EXTOS_BLS_DIR")]
        bls_dir: Option<PathBuf>,
    },
    /// List all generations and their status
    Generations {
        /// Generations root (default: `EXTOS_ROOTFS`)
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
    },
    /// Serve the instanz gRPC control plane over a Unix domain socket (PLAN 8.1.4)
    Serve {
        /// Path to the gRPC control socket. Overrides `EXTOS_INSTANZ_SOCKET`;
        /// defaults to the ARCHITECTURE §15 path (`rpc::DEFAULT_SOCKET`).
        #[arg(long, env = "EXTOS_INSTANZ_SOCKET")]
        socket: Option<PathBuf>,
        /// Control-socket group override (PLAN 8.1.5). Defaults to the §15
        /// daemon group (`extos-admin`, from `libextos::daemons::DEFAULT_SOCKETS`);
        /// `none` (or an empty value) disables the chown entirely.
        #[arg(long)]
        group: Option<String>,
        /// Generations root (default: `EXTOS_ROOTFS`); `Apply` falls back to
        /// the config's `root` key like the CLI
        #[arg(long, env = "EXTOS_ROOTFS")]
        rootfs: Option<PathBuf>,
        /// Boot root the forge writes the initramfs + BLS matrix into
        #[arg(long, env = crate::forge::ENV_BOOT_ROOT)]
        boot_root: Option<PathBuf>,
        /// Legacy BLS entries directory (`gen-<n>.conf` entries, no forge)
        #[arg(long, env = "EXTOS_BLS_DIR")]
        bls_dir: Option<PathBuf>,
        /// Container backend: native, nspawn, runc, crun, chroot
        #[arg(long, env = "EXTOS_CONTAINER_BACKEND")]
        backend: Option<String>,
        /// System config used for `containerPermissions` lookup
        #[arg(long, env = crate::run::ENV_SYSTEM_CONFIG)]
        config: Option<PathBuf>,
        /// Explicit opt-in for level-4 (privileged) launches through this
        /// server; default deny — the same guard as `run --allow-privileged`
        #[arg(long)]
        allow_privileged: bool,
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

/// Validate the two mutually exclusive boot-entry layouts.
///
/// `--boot-root` is the forge mode (initramfs + `extos-<system>-g<n>-<kernel>.conf`
/// matrix); `--bls-dir` is the Phase-2 snapshot mode (`gen-<n>.conf`, no forge).
/// Setting both is ambiguous, so it is a typed error instead of a silent pick.
fn bls_modes(
    boot_root: Option<PathBuf>,
    bls_dir: Option<PathBuf>,
) -> anyhow::Result<(Option<PathBuf>, Option<PathBuf>)> {
    if boot_root.is_some() && bls_dir.is_some() {
        bail!(
            "both --boot-root/EXTOS_BLS_ROOT and --bls-dir/EXTOS_BLS_DIR are set: \
             choose the forge mode (boot root) or the legacy snapshot-entry mode (entries dir)"
        );
    }
    Ok((boot_root, bls_dir))
}

/// Scratch directory the forge stages its tmpfs under.
fn forge_scratch() -> PathBuf {
    std::env::var_os(forge::ENV_FORGE_SCRATCH)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(std::env::temp_dir)
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
        Commands::Apply {
            config,
            rootfs,
            boot_root,
            bls_dir,
        } => {
            let (boot_root, bls_dir) = bls_modes(boot_root, bls_dir)?;
            let system = SystemConfig::load(Path::new(&config))?;
            let rootfs = rootfs_from_config(rootfs, system.root.clone())?;
            let repo = open_repo(&cli.repository, algo)?;
            let cache_dir = repo.root.join("cache");
            let scratch = forge_scratch();
            let mounts = system.mount_sources();
            let options = ApplyOptions {
                rootfs: &rootfs,
                cache_dir: &cache_dir,
                bls_dir: bls_dir.as_deref(),
                boot_root: boot_root.as_deref(),
                forge_scratch: &scratch,
                mounts: &mounts,
            };
            let report = apply(&repo, system, &options)?;
            println!(
                "generation {} → {} ({} op(s), {} phantom row(s), forge {}, bls {}, reaped {} gen(s), lock {})",
                report.generation,
                report.root.display(),
                report.plan_ops,
                report.phantom_rows,
                report.forge,
                report.bls_entries,
                report.reaped.len(),
                report.lockfile.display()
            );
            Ok(())
        }
        Commands::Rollback {
            generation,
            rootfs,
            boot_root,
            bls_dir,
        } => {
            let (boot_root, bls_dir) = bls_modes(boot_root, bls_dir)?;
            let rootfs = require_rootfs(rootfs)?;
            let target = RollbackTarget::parse(generation.as_deref())?;
            rollback(&rootfs, target, boot_root.as_deref(), bls_dir.as_deref())?;
            Ok(())
        }
        Commands::Run {
            profile,
            rootfs,
            level,
            backend,
            program,
            config,
            allow_privileged,
            args,
        } => {
            let rootfs = require_rootfs(rootfs)?;
            // The repository is a *profile lookup* source, not a runtime
            // requirement: opening it lazily (only when a config was named)
            // keeps `instanz run` from creating `/repository` as a side effect.
            let repo = match &config {
                Some(_) => Some(open_repo(&cli.repository, algo)?),
                None => None,
            };
            let options = run::RunOptions {
                rootfs: &rootfs,
                profile: &profile,
                level,
                backend: backend.as_deref(),
                program: program.as_deref(),
                args: &args,
                config: config.as_deref(),
                allow_privileged,
            };
            let code = run::run(repo.as_ref(), &options)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
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
            boot_root,
            bls_dir,
        } => {
            let (boot_root, bls_dir) = bls_modes(boot_root, bls_dir)?;
            let rootfs = require_rootfs(rootfs)?;
            let repo = open_repo(&cli.repository, algo)?;
            let report = gc(
                &repo,
                &rootfs,
                keep_generations as usize,
                boot_root.as_deref(),
                bls_dir.as_deref(),
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
        Commands::Serve {
            socket,
            group,
            rootfs,
            boot_root,
            bls_dir,
            backend,
            config,
            allow_privileged,
        } => {
            // Same mutual-exclusion rule as `apply`/`rollback`/`gc`: the forge
            // boot root and the legacy snapshot-entries dir are two layouts.
            let (boot_root, bls_dir) = bls_modes(boot_root, bls_dir)?;
            let socket = socket.unwrap_or_else(|| PathBuf::from(crate::rpc::DEFAULT_SOCKET));
            let server_config = crate::rpc::InstanzConfig {
                rootfs,
                boot_root,
                bls_dir,
                forge_scratch: forge_scratch(),
                backend,
                system_config: config,
                allow_privileged,
            };
            tracing::info!("Serving instanz control plane on {}", socket.display());
            match group.as_deref() {
                // The §15 default (`extos-admin`) applies when no flag was given.
                Some(flag) => crate::rpc::serve_with_group(
                    &cli.repository,
                    algo,
                    &socket,
                    server_config,
                    Some(flag),
                )?,
                None => crate::rpc::serve(&cli.repository, algo, &socket, server_config)?,
            };
            Ok(())
        }
    }
}
