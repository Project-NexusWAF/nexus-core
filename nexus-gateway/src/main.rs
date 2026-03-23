mod commands;
mod proxy;
mod server;
mod state;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
  name = "nexus-gateway",
  version,
  about = "NexusWAF single-binary gateway"
)]
struct Cli {
  #[arg(
    short,
    long,
    env = "NEXUS_CONFIG",
    default_value = "config/default.toml"
  )]
  config: String,
  #[command(subcommand)]
  command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
  /// Start the gateway process (default)
  Start {
    #[arg(long)]
    listen: Option<String>,
  },
  /// Stop a running gateway process via PID file (Unix only)
  Stop,
  /// Trigger process reload via SIGHUP (Unix only)
  Reload,
  /// Query REST health endpoint
  Status,
  /// Show token source/status (redacted)
  Token,
  /// Validate config and exit
  Check,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  match cli.command.unwrap_or(Cmd::Start { listen: None }) {
    Cmd::Start { listen } => commands::cmd_start(cli.config, listen).await?,
    Cmd::Stop => commands::cmd_stop(cli.config).await?,
    Cmd::Reload => commands::cmd_reload(cli.config).await?,
    Cmd::Status => commands::cmd_status(cli.config).await?,
    Cmd::Token => commands::cmd_token(cli.config).await?,
    Cmd::Check => commands::cmd_check(cli.config).await?,
  }
  Ok(())
}
