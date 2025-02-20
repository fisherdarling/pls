use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::{fs, io::stdin};

use clap::{CommandFactory, Parser};
use color_eyre::eyre::{Context, Result};

use crate::{components::print_pems, pem::parse_pems};

use super::{CommandExt, Format};

/// Parse and report all discoverable x509 or DER encoded entities from a file
/// or stdin. The `--json` output for this command will output an object of:
///
/// ```
/// { certs: ..., csrs: ..., private_keys: ... }
/// ```
///
/// Each of the fields will be an array of objects, even if there is only one
/// e.g. cert. DER discovery is not well supported at the moment.
///
/// Supports:
///
/// 1. x509 certs
/// 2. x509 csrs
/// 3. private keys
/// 4. public keys
/// 5. DER encoded entities (kinda)
#[derive(Default, Clone, Debug, Parser)]
pub struct Parse {
    /// File to read data from. Defaults to `stdin`.
    pub file: Option<PathBuf>,
}

impl CommandExt for Parse {
    async fn run(self, format: Format) -> Result<()> {
        let data = if let Some(path) = self.file {
            tracing::info!("parsing certificates from file: {}", path.display());
            fs::read(&path).with_context(|| format!("Reading {}", path.display()))?
        } else {
            tracing::info!("parsing certificates from stdin");
            let mut buffer = Vec::new();

            let stdin = stdin();
            if stdin.is_terminal() {
                // todo: tracing / terminal support
                tracing::error!("stdin is a TTY, please provide a file or pipe data into stdin");
                let mut clap_command = <crate::Cli as CommandFactory>::command();
                clap_command.print_long_help().unwrap();
                return Ok(()); // should this be an error?
            }

            io::stdin()
                .read_to_end(&mut buffer)
                .context("Reading stdin")?;
            buffer
        };

        let pems = parse_pems(&data).flatten();
        print_pems(format, pems)?;

        Ok(())
    }
}
