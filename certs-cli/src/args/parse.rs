use std::path::PathBuf;

use anyhow::Context as _;
use certs_parser::{ParsedItem, Parser};
use clap::Parser as ClapParser;

use crate::context::Ctx;

#[derive(Debug, ClapParser)]
pub struct ParseArgs {
    /// Path to the file containing PEM data to parse
    file: PathBuf,
}

impl ParseArgs {
    pub fn run(self, _ctx: &Ctx) -> anyhow::Result<()> {
        let data = std::fs::read(&self.file)
            .with_context(|| format!("Failed to read file: {}", self.file.display()))?;

        let parser = Parser::new(&data);

        for item in parser.parse() {
            match item {
                ParsedItem::SpannedParsedPem(pem) => {
                    println!("{:#?}", pem);
                }
                ParsedItem::DecodeFailedPem(raw_pem, error) => {
                    println!("Failed to decode PEM at {}:{}: {}", 
                        raw_pem.line(), raw_pem.col(), error);
                }
            }
        }

        Ok(())
    }
}