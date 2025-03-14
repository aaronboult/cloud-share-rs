use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(
    name = "cloud-share",
    version,
    about = "Cloud file synchronization tool",
    disable_help_subcommand = true,
)]

pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Verbose mode
    #[arg(short, long, global=true)]
    pub verbose: Option<bool>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Download files from cloud storage
    Pull(PullArgs),

    /// Upload files to cloud storage
    Push(PushArgs),

    /// Initialize a new synchronization configuration
    Init(InitArgs),

    /// Reset synchronization state for a path
    Reset(ResetArgs),

    /// Set the remote url
    SetRemote(SetRemoteArgs),

    /// Exclude paths from synchronization
    Exclude(ExcludeArgs),

    /// Include paths in synchronization
    Include(ExcludeArgs),

    /// Show synchronization status
    Status,

    /// Lists all conflicts that need to be resolved
    ListConflicts,

    /// List registry entries
    ListRegistry,

    /// List excluded paths
    ListExclusions,

}

#[derive(Args)]
pub struct PullArgs {
    /// Custom path to synchronize
    #[arg(long)]
    pub path: Option<String>,
}

#[derive(Args)]
pub struct PushArgs {
    /// Custom path to synchronize
    #[arg(long)]
    pub path: Option<String>,
}

#[derive(Args)]
pub struct InitArgs {
    /// Cloud storage endpoint URL (required)
    #[arg(short, long, required = true)]
    pub url: String,

    /// Local path for synchronization
    #[arg(long)]
    pub path: Option<String>,
}

#[derive(Args)]
pub struct ResetArgs {
    /// Path to reset
    pub path: Option<String>,
}


#[derive(Args)]
pub struct SetRemoteArgs {
    /// Cloud storage endpoint URL (required)
    #[arg(short, long, required = true)]
    pub url: String,
}

#[derive(Args)]
pub struct ExcludeArgs {
    /// Path to exclude from synchronization
    pub path: String,

    /// File patterns to exclude (pipe-separated)
    #[arg(long)]
    pub filename_pattern: Option<String>,
}