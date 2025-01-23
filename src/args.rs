use crate::{
    commands::{connect::Connect, parse::Parse, Format},
    CommandExt,
};
use clap::{Parser, Subcommand};

/// `pls` is a human-first tool for working with x509 certificates and other
/// WebPKI/TLS primitives. You ask it nicely to parse a file or get a server's
/// certs and It Just Works.
///
/// # Examples:
///
/// pls parse ./cert.pem
///
/// pls parse ./cert.pem | jq
///
/// pls connect https://example.com
#[derive(Default, Debug, Parser)]
#[command(name = "pls", version = "0.1", author = "Fisher")]
pub struct Cli {
    /// Sets the level of verbosity (-v, -vv, -vvv, etc.)
    #[command(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// Output the results as JSON. Defaults to `true` if stdout is not a TTY.
    #[arg(long, global = true, conflicts_with = "text", conflicts_with = "pem")]
    json: bool,

    /// Output the results as human-readable text. Defaults to `true` if stdout is
    /// a TTY.
    #[arg(long, global = true, conflicts_with = "json", conflicts_with = "pem")]
    text: bool,

    /// Output the results as PEM encoded data. Defaults to `false`.
    #[arg(long, global = true, conflicts_with = "json", conflicts_with = "text")]
    pem: bool,

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

    pub fn format(&self) -> Format {
        Format::from_args(self.text, self.json, self.pem)
    }
}

#[derive(Default, Debug, Clone, Subcommand)]
pub enum Command {
    Parse(Parse),
    Connect(Connect),
    #[default]
    #[clap(skip)]
    NoCommand,
}

impl Command {
    pub async fn run(self, format: Format) -> color_eyre::Result<()> {
        match self {
            Command::Parse(cert) => cert.run(format).await,
            Command::Connect(connect) => connect.run(format).await,
            Command::NoCommand => {
                let mut clap_command = <Cli as clap::CommandFactory>::command();
                clap_command.print_long_help()?;
                Ok(())
            }
        }
    }
}
