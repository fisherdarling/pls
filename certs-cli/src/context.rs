use std::{
    io::IsTerminal,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use certs_display::OutputFormat;
use certs_settings::Settings;
use clap_verbosity_flag::Verbosity;

#[derive(Debug, Clone)]
pub struct Ctx {
    start: Instant,
    settings: Settings,
    output: OutputFormat,
    verbosity: Verbosity,
    is_terminal: bool,
}

impl Ctx {
    pub fn new(
        settings: Settings,
        output: OutputFormat,
        verbosity: Verbosity,
        is_terminal: bool,
    ) -> Self {
        Self {
            start: Instant::now(),
            settings,
            output,
            verbosity,
            is_terminal,
        }
    }

    pub fn from_args(args: &crate::args::Cli) -> anyhow::Result<Self> {
        let settings = if let Some(config_path) = &args.config {
            let config_path = config_path
                .canonicalize()
                .context("Failed to canonicalize config path")?;

            foundations::settings::from_file(&config_path).with_context(|| {
                format!("Failed to read config file at: {}", config_path.display())
            })?
        } else {
            Settings::default()
        };

        let output: OutputFormat = args.output.clone().into();
        let verbosity = args.verbose.clone();
        let is_terminal = std::io::stdout().is_terminal();

        Ok(Self::new(settings, output, verbosity, is_terminal))
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn output(&self) -> &OutputFormat {
        &self.output
    }

    pub fn verbosity(&self) -> &Verbosity {
        &self.verbosity
    }

    pub fn is_terminal(&self) -> bool {
        self.is_terminal
    }
}
