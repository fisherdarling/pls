use std::ops::Range;

use anyhow::Context;
use pls_types::{
    cert::Cert,
    csr::Csr,
    key::{DhParams, EcPrivateKey, PrivateKey, PublicKey, RsaPrivateKey},
};

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

#[derive(Debug)]
pub enum ParsedItem<'a> {
    /// A successfully decoded PEM:
    SpannedParsedPem(SpannedParsedPem),
    /// A PEM that failed to decode:
    DecodeFailedPem(Spanned<lexer::RawPem<'a>>, anyhow::Error),
}

#[derive(Debug)]
pub struct SpannedParsedPem {
    raw: Spanned<lexer::DecodedRawPem>,
    value: ParsedPem,
}

impl SpannedParsedPem {
    pub fn value(&self) -> &ParsedPem {
        &self.value
    }

    pub fn into_cert(self) -> Option<Cert> {
        match self.value {
            ParsedPem::Cert(cert) => Some(cert),
            _ => None,
        }
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
            "CERTIFICATE" => {
                ParsedPem::Cert(Cert::from_der(raw.data.der()).with_context(|| {
                    format!(
                        "parsing CERTIFICATE at {}:{}, der={}",
                        raw.line(),
                        raw.col(),
                        boring::base64::encode_block(raw.data.der()),
                    )
                })?)
            }
            "CERTIFICATE REQUEST" => ParsedPem::Csr(
                Csr::from_der(raw.data.der())
                    .with_context(|| format!("parsing CSR at {}:{}", raw.line(), raw.col()))?,
            ),
            "RSA PRIVATE KEY" => {
                let key = RsaPrivateKey::from_der(raw.data.der()).with_context(|| {
                    format!("parsing RSA PRIVATE KEY at {}:{}", raw.line(), raw.col(),)
                })?;
                ParsedPem::RsaPrivateKey(key)
            }
            "PUBLIC KEY" => {
                let key = PublicKey::from_der(raw.data.der()).with_context(|| {
                    format!("parsing PUBLIC KEY at {}:{}", raw.line(), raw.col())
                })?;
                ParsedPem::PublicKey(key)
            }
            "DH PARAMETERS" => {
                let params = DhParams::from_der(raw.data.der()).with_context(|| {
                    format!("parsing DH PARAMETERS at {}:{}", raw.line(), raw.col())
                })?;
                ParsedPem::DhParams(params)
            }
            "PRIVATE KEY" => {
                let key = PrivateKey::from_der(raw.data.der()).with_context(|| {
                    format!("parsing PRIVATE KEY at {}:{}", raw.line(), raw.col())
                })?;
                ParsedPem::PrivateKey(key)
            }
            "EC PRIVATE KEY" => {
                let key = EcPrivateKey::from_der(raw.data.der()).with_context(|| {
                    format!("parsing EC PRIVATE KEY at {}:{}", raw.line(), raw.col())
                })?;
                ParsedPem::EcPrivateKey(key)
            }
            _ => return Err(anyhow::anyhow!("unknown PEM type: {}", &***raw.label())),
        };
        Ok(Self { raw, value })
    }
}

#[derive(Debug)]
pub enum ParsedPem {
    Cert(Cert),
    Csr(Csr),
    RsaPrivateKey(RsaPrivateKey),
    EcPrivateKey(EcPrivateKey),
    PublicKey(PublicKey),
    PrivateKey(PrivateKey),
    DhParams(DhParams),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Spanned<T> {
    span: Range<usize>,
    line: usize,
    col: usize,
    data: T,
}

impl<T> Spanned<T> {
    pub fn new(data: T, span: Range<usize>, line: usize, col: usize) -> Self {
        Self {
            data,
            span,
            line,
            col,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Parser;

    #[test]
    fn parse_json() {
        let data = [
            45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45,
            45, 45, 45, 45, 92, 110, 77, 69, 52, 119, 69, 65, 89, 72, 75, 111, 90, 73, 122, 106,
            48, 67, 65, 81, 89, 70, 75, 52, 69, 69, 65, 67, 69, 68, 79, 103, 65, 69, 115, 65, 69,
            56, 98, 55, 47, 50, 56, 74, 47, 115, 50, 104, 119, 109, 80, 118, 90, 84, 109, 100, 84,
            80, 109, 74, 121, 108, 47, 69, 43, 80, 92, 110, 47, 119, 47, 112, 52, 102, 47, 47, 47,
            47, 47, 120, 49, 85, 56, 88, 116, 113, 70, 54, 89, 85, 49, 81, 84, 47, 101, 87, 75, 82,
            103, 66, 110, 90, 88, 117, 98, 112, 103, 47, 83, 85, 85, 61, 92, 110, 45, 45, 45, 45,
            45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45,
        ];
        println!("{:?}", String::from_utf8_lossy(&data));
        let parser = Parser::new(&data);

        for pem in parser.parse() {
            println!("{:?}", pem);
        }
    }
}
