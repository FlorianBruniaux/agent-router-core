use clap::Parser;

use crate::command::Commands;

#[derive(Parser)]
#[command(name = "agent-router", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}
