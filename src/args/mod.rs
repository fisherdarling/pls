mod parse;

use clap::{Parser, Subcommand};
use parse::Parse;

/// The CLI app for manipulating x509 certificates and TLS data.
#[derive(Debug, Parser)]
#[command(name = "teal", version = "1.0", author = "Fisher")]
pub struct Cli {
    /// Sets the level of verbosity (-v, -vv, -vvv, etc.)
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[command(subcommand)]
    command: Option<Command>, // the default command is `cert`
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    pub fn command(&self) -> Command {
        self.command
            .clone()
            .unwrap_or(Command::Parse(Parse::default()))
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    Parse(Parse),
}
