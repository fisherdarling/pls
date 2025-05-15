use std::{ops::Range, path::Path};

use pls_types::{cert::Cert, csr::Csr};

mod lexer;

pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn parse(&'a self) -> impl Iterator<Item = ParsedItem<'a>> {
        lexer::pems(self.data).map(move |pem| match pem.decode() {
            Ok(decoded) => {
                let spanned_parsed_pem = SpannedParsedPem::from_raw(Spanned {
                    span: pem.span(),
                    line: pem.line(),
                    col: pem.col(),
                    data: decoded,
                });

                match spanned_parsed_pem {
                    Ok(parsed_pem) => ParsedItem::SpannedParsedPem(parsed_pem),
                    Err(e) => ParsedItem::DecodeFailedPem(pem, e),
                }
            }

            Err(e) => ParsedItem::DecodeFailedPem(pem, e),
        })
    }
}

pub enum ParsedItem<'a> {
    /// A successfully decoded PEM:
    SpannedParsedPem(SpannedParsedPem),
    /// A PEM that failed to decode:
    DecodeFailedPem(Spanned<lexer::RawPem<'a>>, anyhow::Error),
}

pub struct SpannedParsedPem {
    raw: Spanned<lexer::DecodedRawPem>,
    value: ParsedPem,
}

impl SpannedParsedPem {
    pub fn value(&self) -> &ParsedPem {
        &self.value
    }

    pub fn label(&self) -> &str {
        &***self.raw.label()
    }

    pub fn span(&self) -> Range<usize> {
        self.raw.span()
    }

    pub fn line(&self) -> usize {
        self.raw.line()
    }

    pub fn col(&self) -> usize {
        self.raw.col()
    }

    pub fn der(&self) -> &[u8] {
        self.raw.data.der()
    }

    fn from_raw(raw: Spanned<lexer::DecodedRawPem>) -> Result<Self, anyhow::Error> {
        let value = match &***raw.label() {
            "CERTIFICATE" => ParsedPem::Cert(Cert::from_der(raw.data.der())?),
            "CERTIFICATE REQUEST" => ParsedPem::Csr(Csr::from_der(raw.data.der())?),
            _ => return Err(anyhow::anyhow!("unknown PEM type: {}", &***raw.label())),
        };
        Ok(Self { raw, value })
    }
}

pub enum ParsedPem {
    Cert(Cert),
    Csr(Csr),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Spanned<T> {
    span: Range<usize>,
    line: usize,
    col: usize,
    data: T,
}
