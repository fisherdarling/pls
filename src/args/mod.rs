mod connect;
mod parse;

use std::io::{self, IsTerminal};

use clap::{Parser, Subcommand};
use connect::Connect;
use iocraft::{element, prelude::View, ElementExt, FlexDirection};
use parse::Parse;

use crate::{components::x509::X509View, simple_cert::SimpleCert};

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
    Connect(Connect),
    #[default]
    #[clap(skip)]
    NoCommand,
}

fn print_certs(certs: Vec<SimpleCert>, text: bool, json: bool) -> color_eyre::Result<()> {
    let print_json = json || (!text && !io::stdout().is_terminal());
    let print_text = text || (!json && io::stdout().is_terminal());

    if print_json {
        println!("{}", serde_json::to_string(&certs)?);
    } else if print_text {
        element!(View(flex_direction: FlexDirection::Column, gap: 1) {
            #(certs.into_iter().map(|cert| element!(X509View(cert))))
        })
        .print();
    } else {
        // todo: not sure this is possible to reach due to `conflicts_with`
        // in the args
        eprintln!("No output format specified");
    }

    Ok(())
}
