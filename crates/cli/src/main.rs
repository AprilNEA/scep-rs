//! `scep` command line.
//!
//! This release provides `serve`, a file-backed SCEP server that answers
//! `GetCACaps` and `GetCACert` and records `PKIOperation` messages for
//! inspection. The client commands and certificate issuance follow in the next
//! release; the design and progress live in <https://github.com/AprilNEA/scep-rs>.

use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

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
