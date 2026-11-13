//! `scep` command line.
//!
//! `serve` provides discovery, capture-only operation and a static-challenge
//! test CA for initial enrollment. The enrollment client is not implemented.

use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

mod ca;
mod serve;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve SCEP over HTTP for one CA or RA certificate and key.
    Serve(serve::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    match Cli::parse().command {
        Command::Serve(args) => serve::run(args).await,
    }
}
