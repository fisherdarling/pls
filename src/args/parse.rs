use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;
use iocraft::prelude::*;

use crate::{
    components::x509::X509View,
    x509::{self, SimpleCert},
};

/// Perform operations on certificates
#[derive(Default, Clone, Debug, Parser)]
pub struct Parse {
    /// Optional file path to read data from. Reads from stdin if omitted.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

impl Parse {
    pub fn run(self) -> Result<()> {
        let data = if let Some(path) = self.file {
            fs::read(path)?
        } else {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            buffer
        };

        let cert = x509::parse_auto(&data)?;
        let simple_cert = SimpleCert::from(cert);

        element!(X509View(cert: simple_cert)).print();

        // println!("{simple_cert}");
        Ok(())
    }
}
