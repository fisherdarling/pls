mod parse;

use clap::{Parser, Subcommand};
use parse::Parse;

/// The CLI app for manipulating x509 certificates and TLS data.
#[derive(Default, Debug, Parser)]
#[command(name = "pls", version = "0.1", author = "Fisher")]
pub struct Cli {
    /// Sets the level of verbosity (-v, -vv, -vvv, etc.)
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[command(subcommand)]
    command: Command, // the default command is `cert`
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    pub fn command(&self) -> Command {
        self.command.clone()
    }
}

#[derive(Default, Debug, Clone, Subcommand)]
pub enum Command {
    Parse(Parse),
    #[default]
    #[clap(skip)]
    NoCommand,
}
