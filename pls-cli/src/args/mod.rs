use crate::{args::scan::ScanArgs, context::OutputFormat};
use clap::Parser;
use clap_verbosity_flag::Verbosity;
use std::path::PathBuf;

mod scan;

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(flatten)]
    pub verbose: Verbosity,

    #[command(flatten)]
    pub output: OutputFlags,

    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn parse() -> Self {
        Self::parse_from(std::env::args())
    }
}

#[derive(Debug, Parser)]
pub enum Command {
    Scan(ScanArgs),
}

#[derive(Debug, Parser, Clone, Copy, PartialEq, Eq)]
pub struct OutputFlags {
    #[arg(short, long)]
    pub json: bool,
    #[arg(short, long)]
    pub text: bool,
    #[arg(short, long)]
    pub pem: bool,
}

impl From<OutputFlags> for OutputFormat {
    fn from(flags: OutputFlags) -> Self {
        if flags.json {
            OutputFormat::Json
        } else if flags.text {
            OutputFormat::Text
        } else if flags.pem {
            OutputFormat::Pem
        } else {
            OutputFormat::Json
        }
    }
}
