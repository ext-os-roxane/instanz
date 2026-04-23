use clap::{Parser, Subcommand};

/// instanz — ExtOS Hypervisor & Runlevel Engine
///
/// Manages system snapshots, executes the Symlink/Reflink Weaver,
/// provisions containers (Levels 0-4), and orchestrates the
/// declarative boot lifecycle.
#[derive(Parser)]
#[command(name = "instanz", version, about, long_about = None)]
struct Cli {
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
    /// Apply a system configuration: snapshot → fetch → weave → initramfs → BLS
    Apply {
        /// Path to the system configuration file
        #[arg(default_value = "/config/systems/default.nix")]
        config: String,
    },
    /// Rollback to a previous generation
    Rollback {
        /// Generation number (default: previous)
        #[arg(long)]
        generation: Option<u64>,
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
        #[arg(long, default_value = "3")]
        keep_generations: u32,
    },
    /// List all generations and their status
    Generations,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Evaluate { config } => {
            tracing::info!("instanz evaluate: {config}");
            todo!("M6.1: DAG evaluation")
        }
        Commands::Apply { config } => {
            tracing::info!("instanz apply: {config}");
            todo!("M8.2: Full apply pipeline")
        }
        Commands::Rollback { generation } => {
            tracing::info!("instanz rollback: gen={generation:?}");
            todo!("M8.3: Rollback")
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
        Commands::Gc { keep_generations } => {
            tracing::info!("instanz gc: keeping {keep_generations} generations");
            todo!("M8: Generation garbage collection")
        }
        Commands::Generations => {
            tracing::info!("instanz generations");
            todo!("M8.4: Generation listing")
        }
    }
}
