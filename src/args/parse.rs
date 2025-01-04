use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Perform operations on certificates
#[derive(Default, Clone, Debug, Parser)]
pub struct Parse {
    /// Optional file path to read data from. Reads from stdin if omitted.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {}

impl Parse {
    pub fn run(self) -> color_eyre::Result<()> {
        println!("{:?}", self);
        Ok(())
    }
}
