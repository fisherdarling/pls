//! Display types in [`cert-types`] in a human-readable format or JSON.
//!
//! The primary trait is [`Repr`], which will be implemented for all types in [`cert-types`].
//!
//! The [`Config`] struct is used to configure the output.
//!
//! The [`OutputFormat`] enum is used to specify the output format.

use iocraft::AnyElement;

mod impls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub print_public_keys: bool,
    pub print_private_keys: bool,
    pub print_sans: bool,
    pub print_fingerprints: bool,
    pub print_expiry: bool,
    pub print_serial: bool,
    pub print_issuer: bool,
    pub print_subject: bool,
    pub print_paths: bool,
    pub print_line_and_col: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            print_public_keys: true,
            print_private_keys: false,
            print_sans: true,
            print_fingerprints: true,
            print_expiry: true,
            print_serial: true,
            print_issuer: true,
            print_subject: true,
            print_paths: true,
            print_line_and_col: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Text,
    Pem,
}

pub trait Repr {
    fn text(&self, config: &Config) -> anyhow::Result<AnyElement<'static>>;
    fn json(&self, config: &Config) -> anyhow::Result<serde_json::Value>;
}
