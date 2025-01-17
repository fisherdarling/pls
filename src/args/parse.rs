use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::{fs, io::stdin};

use clap::{CommandFactory, Parser};
use color_eyre::eyre::Result;

use crate::{simple_cert::SimpleCert, x509_parser};

use super::print_certs;

/// Parse and report all x509 or DER certs from a file or stdin. The --json
/// output for this command will always output an array, even if there is only
/// one cert.
#[derive(Default, Clone, Debug, Parser)]
pub struct Parse {
    /// Output the results as JSON. Defaults to true if stdout is not a TTY.
    #[arg(long, conflicts_with = "text")]
    json: bool,
    /// Output the results as human-readable text. Defaults to true if stdout is
    /// a TTY.
    #[arg(long)]
    text: bool,
    /// File to read data from. Reads from stdin if omitted.
    file: Option<PathBuf>,
}

impl Parse {
    pub fn run(self) -> Result<()> {
        let data = if let Some(path) = self.file {
            fs::read(path)?
        } else {
            let mut buffer = Vec::new();

            let stdin = stdin();
            if stdin.is_terminal() {
                // todo: tracing / terminal support
                eprintln!("stdin is a TTY, please provide a file or pipe data into stdin");
                let mut clap_command = <crate::Cli as CommandFactory>::command();
                clap_command.print_long_help().unwrap();
                return Ok(()); // should this be an error?
            }

            io::stdin().read_to_end(&mut buffer)?;
            buffer
        };

        let certs = x509_parser::parse_auto(&data)?
            .into_iter()
            .map(SimpleCert::from);

        print_certs(certs.collect(), self.text, self.json)?;

        Ok(())
    }
}
