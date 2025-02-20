use csr::print_csrs;
use jiff::{Span, SpanRound, Unit, Zoned};
use private_key::print_private_keys;
use public_key::print_public_keys;
use serde::Serialize;
use x509::print_certs;

use crate::{
    commands::Format,
    pem::{ParsedPem, Pem},
    x509::{SimpleCert, SimpleCsr, SimplePrivateKey, SimplePublicKey},
};

pub mod connection;
pub mod csr;
pub mod keys;
pub mod private_key;
pub mod public_key;
pub mod x509;

pub(crate) fn round_relative_human(span: Span, relative_to: Zoned) -> Span {
    let round_config = if span.total((Unit::Year, relative_to.date())).unwrap().abs() > 1.0 {
        SpanRound::new()
            .largest(jiff::Unit::Year)
            .smallest(jiff::Unit::Month)
            .relative(&relative_to)
    // if it's in months from now:
    } else if span.total((Unit::Month, relative_to.date())).unwrap().abs() > 1.0 {
        SpanRound::new()
            .largest(jiff::Unit::Month)
            .smallest(jiff::Unit::Day)
            .relative(&relative_to)
    // it's in days from now:
    } else {
        SpanRound::new()
            .largest(jiff::Unit::Day)
            .smallest(jiff::Unit::Minute)
            .relative(&relative_to)
    };

    span.round(round_config).expect("unable to round span")
}

pub(crate) fn print_pems(
    format: Format,
    pems: impl IntoIterator<Item = Pem>,
) -> Result<(), color_eyre::eyre::Error> {
    #[derive(Debug, Default, Serialize)]
    struct ParseResult {
        pub certs: Vec<SimpleCert>,
        pub csrs: Vec<SimpleCsr>,
        pub private_keys: Vec<SimplePrivateKey>,
        pub public_keys: Vec<SimplePublicKey>,
    }

    let mut parse_result = ParseResult::default();
    for pem in pems {
        tracing::debug!("parsing pem: {:?}", pem);

        match pem.into_parsed_pem() {
            ParsedPem::Cert(cert) => parse_result.certs.push(SimpleCert::from(cert)),
            ParsedPem::CertReq(csr) => parse_result.csrs.push(SimpleCsr::from(csr)),
            ParsedPem::PrivateKey(key) => {
                parse_result.private_keys.push(SimplePrivateKey::from(key))
            }
            ParsedPem::RsaPrivateKey(key) => {
                parse_result.private_keys.push(SimplePrivateKey::from(key))
            }
            ParsedPem::PublicKey(key) => parse_result.public_keys.push(SimplePublicKey::from(key)),
            variant => {
                tracing::warn!("unsupported pem variant: {:?}", variant);
            }
        }
    }

    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&parse_result)?);
        }
        Format::Text | Format::Pem => {
            if !parse_result.certs.is_empty() {
                print_certs(parse_result.certs, format)?;
            }

            if !parse_result.csrs.is_empty() {
                print_csrs(parse_result.csrs, format)?;
            }

            if !parse_result.public_keys.is_empty() {
                tracing::info!("{:?} public keys", parse_result.public_keys);
                print_public_keys(parse_result.public_keys, format)?;
            }

            if !parse_result.private_keys.is_empty() {
                print_private_keys(parse_result.private_keys, format)?;
            }
        }
    }

    Ok(())
}
