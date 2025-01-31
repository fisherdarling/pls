use std::{borrow::Cow, convert::Infallible, ops::Range, str::FromStr, sync::LazyLock};

use boring::{
    ec::EcKey,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    x509::{X509Req, X509},
};
use regex::bytes::{Regex, RegexBuilder};

static PEM_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(
        r"(?P<pem>-----BEGIN (?P<header_label>.*?)-----(?:\n|\\n)?(?P<cert_data>.*?)(?:\n|\\n)?-----END .*?-----)",
    )
    .dot_matches_new_line(true)
    .build()
    .expect("Failed to compile PEM regex")
});

static REMOVE_WHITESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\s|\\n)+").expect("Failed to compile whitespace regex"));

fn extract_raw_pems(data: &[u8]) -> impl Iterator<Item = anyhow::Result<RawPem<'_>>> {
    PEM_REGEX.captures_iter(data).map(|capture| {
        let pem = capture.name("pem").unwrap();
        let header_label = capture.name("header_label").unwrap();
        let cert_data = capture.name("cert_data").unwrap();

        let label = header_label.as_bytes();
        let cleaned_data = REMOVE_WHITESPACE.replace_all(cert_data.as_bytes(), b"");
        let data = boring::base64::decode_block(&String::from_utf8_lossy(&cleaned_data))?;

        Ok(RawPem {
            span: pem.range(),
            label: String::from_utf8_lossy(label),
            data,
        })
    })
}

pub(crate) fn parse_pems(data: &[u8]) -> impl Iterator<Item = anyhow::Result<Pem>> + use<'_> {
    extract_raw_pems(data).flatten().map(Pem::try_from)
}

#[derive(Debug)]
pub struct RawPem<'a> {
    span: Range<usize>,
    label: Cow<'a, str>,
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct Pem {
    span: Range<usize>,
    label: Label,
    parsed: ParsedPem,
}

impl Pem {
    pub fn span(&self) -> Range<usize> {
        self.span.clone()
    }

    pub fn label(&self) -> &Label {
        &self.label
    }

    pub fn into_cert(self) -> Option<X509> {
        self.parsed.into_cert()
    }

    pub fn into_parsed_pem(self) -> ParsedPem {
        self.parsed
    }
}

impl TryFrom<RawPem<'_>> for Pem {
    type Error = anyhow::Error;

    fn try_from(value: RawPem) -> Result<Self, Self::Error> {
        let parsed = match value.label.parse()? {
            Label::Certificate => ParsedPem::Cert(X509::from_der(&value.data)?),
            Label::CertificateRequest => ParsedPem::CertReq(X509Req::from_der(&value.data)?),
            Label::PublicKey => ParsedPem::PublicKey(PKey::public_key_from_der(&value.data)?),
            Label::RsaPublicKey => ParsedPem::RsaPublicKey(Rsa::public_key_from_der(&value.data)?),
            Label::RsaPrivateKey => {
                ParsedPem::RsaPrivateKey(Rsa::private_key_from_der(&value.data)?)
            }
            Label::PrivateKey => ParsedPem::PrivateKey(PKey::private_key_from_der(&value.data)?),
            Label::ECPrivateKey => {
                ParsedPem::ECPrivateKey(EcKey::private_key_from_der(&value.data)?)
            }
            Label::Unknown(s) => return Err(anyhow::anyhow!("Unknown PEM label: {}", s)),
        };

        Ok(Self {
            span: value.span,
            label: value.label.parse()?,
            parsed,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Label {
    Certificate,
    CertificateRequest,
    PublicKey,
    RsaPublicKey,
    RsaPrivateKey,
    PrivateKey,
    ECPrivateKey,
    Unknown(String),
}

impl FromStr for Label {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Infallible> {
        Ok(match s {
            "CERTIFICATE" => Self::Certificate,
            "CERTIFICATE REQUEST" => Self::CertificateRequest,
            "PUBLIC KEY" => Self::PublicKey,
            "RSA PUBLIC KEY" => Self::RsaPublicKey,
            "RSA PRIVATE KEY" => Self::RsaPrivateKey,
            "PRIVATE KEY" => Self::PrivateKey,
            "EC PRIVATE KEY" => Self::ECPrivateKey,
            _ => Self::Unknown(s.to_string()),
        })
    }
}

pub enum ParsedPem {
    /// -----BEGIN CERTIFICATE-----
    Cert(X509),
    /// -----BEGIN CERTIFICATE REQUEST-----
    CertReq(X509Req),
    /// -----BEGIN PUBLIC KEY-----
    PublicKey(PKey<Public>),
    /// -----BEGIN RSA PUBLIC KEY-----
    RsaPublicKey(Rsa<Public>),
    /// -----BEGIN RSA PRIVATE KEY-----
    RsaPrivateKey(Rsa<Private>),
    /// -----BEGIN PRIVATE KEY-----
    PrivateKey(PKey<Private>),
    /// -----BEGIN EC PRIVATE KEY-----
    ECPrivateKey(EcKey<Private>),
}

impl ParsedPem {
    pub fn into_cert(self) -> Option<X509> {
        match self {
            Self::Cert(cert) => Some(cert),
            _ => None,
        }
    }

    pub fn into_cert_req(self) -> Option<X509Req> {
        match self {
            Self::CertReq(cert_req) => Some(cert_req),
            _ => None,
        }
    }

    pub fn into_public_key(self) -> Option<PKey<Public>> {
        match self {
            Self::PublicKey(pkey) => Some(pkey),
            _ => None,
        }
    }

    pub fn into_rsa_public_key(self) -> Option<Rsa<Public>> {
        match self {
            Self::RsaPublicKey(rsa) => Some(rsa),
            _ => None,
        }
    }

    pub fn into_rsa_private_key(self) -> Option<Rsa<Private>> {
        match self {
            Self::RsaPrivateKey(rsa) => Some(rsa),
            _ => None,
        }
    }

    pub fn into_private_key(self) -> Option<PKey<Private>> {
        match self {
            Self::PrivateKey(pkey) => Some(pkey),
            _ => None,
        }
    }

    pub fn into_ec_private_key(self) -> Option<EcKey<Private>> {
        match self {
            Self::ECPrivateKey(ec) => Some(ec),
            _ => None,
        }
    }
}

impl std::fmt::Debug for ParsedPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cert(_) => write!(f, "X509Certificate"),
            Self::CertReq(_) => write!(f, "X509CertificateRequest"),
            Self::PublicKey(_) => write!(f, "PublicKey"),
            Self::RsaPublicKey(_) => write!(f, "RsaPublicKey"),
            Self::RsaPrivateKey(_) => write!(f, "RsaPrivateKey"),
            Self::PrivateKey(_) => write!(f, "PrivateKey"),
            Self::ECPrivateKey(_) => write!(f, "ECPrivateKey"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::x509::SimpleCert;

    use super::*;

    #[test]
    fn single_pem() {
        let data = include_bytes!("../../test-data/lan-fish.pem");

        let mut pems: Vec<_> = extract_raw_pems(data)
            .flatten()
            .map(Pem::try_from)
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(pems.len(), 1);
        let cert = pems.pop().unwrap().parsed.into_cert().unwrap();

        let simple_cert = crate::x509::SimpleCert::from(cert);
        assert_eq!(
            simple_cert.fingerprints.sha256,
            "876172fb012989edbc93d2c4c34399f1dff9b5e90f0f30b9c6d2ed82ec184620"
        );
    }

    #[test]
    fn indented_pem() {
        let data = include_bytes!("../../test-data/indented.pem");

        let mut pems: Vec<_> = extract_raw_pems(data)
            .flatten()
            .map(Pem::try_from)
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(pems.len(), 1);
        let cert = pems.pop().unwrap().parsed.into_cert().unwrap();

        let simple_cert = crate::x509::SimpleCert::from(cert);
        assert_eq!(
            simple_cert.fingerprints.sha256,
            "876172fb012989edbc93d2c4c34399f1dff9b5e90f0f30b9c6d2ed82ec184620"
        );
    }

    #[test]
    fn chain() {
        let data = include_bytes!("../../test-data/chain.pem");

        let certs: Vec<SimpleCert> = extract_raw_pems(data)
            .flatten()
            .flat_map(Pem::try_from)
            .flat_map(|pem| pem.parsed.into_cert())
            .map(SimpleCert::from)
            .collect();

        assert_eq!(certs.len(), 3);

        assert_eq!(
            certs[0].fingerprints.sha256,
            "876172fb012989edbc93d2c4c34399f1dff9b5e90f0f30b9c6d2ed82ec184620"
        );
        assert_eq!(
            certs[1].fingerprints.sha256,
            "065ab7d2a050f947587121765d8d070c0e1330d5798faa42c2072749ed293762"
        );
        assert_eq!(
            certs[2].fingerprints.sha256,
            "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470"
        );
    }

    #[test]
    fn json_chain() {
        let data = include_bytes!("../../test-data/pems.json");

        let certs: Vec<SimpleCert> = extract_raw_pems(data)
            .flatten()
            .flat_map(Pem::try_from)
            .flat_map(|pem| pem.parsed.into_cert())
            .map(SimpleCert::from)
            .collect();

        assert_eq!(certs.len(), 2);

        assert_eq!(
            certs[0].fingerprints.sha256,
            "73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699"
        );
        assert_eq!(
            certs[1].fingerprints.sha256,
            "1f8eb9e9a8e066cc5b3833e06b3129764b622639d5b163f600e1c79120bf3eed"
        );
    }

    #[test]
    fn private_key_rsa() {
        let data = include_bytes!("../../test-data/private-keys/begin-rsa-private-key.pem");

        let mut pems: Vec<_> = extract_raw_pems(data)
            .flatten()
            .map(Pem::try_from)
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(pems.len(), 1);
        let parsed = pems.pop().unwrap().parsed;

        let rsa = parsed.into_rsa_private_key().unwrap();
        assert_eq!(rsa.size(), 2048 / 8);
    }

    #[test]
    fn wikipedia_private_key() {
        let data = include_bytes!("../../test-data/private-keys/wikipedia-begin-private-key.pem");

        let mut pems: Vec<_> = extract_raw_pems(data)
            .flatten()
            .map(Pem::try_from)
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(pems.len(), 1);
        let parsed = pems.pop().unwrap().parsed;

        let rsa = parsed.into_private_key().unwrap().rsa().unwrap();
        assert_eq!(rsa.size(), 512 / 8);
    }

    #[test]
    // https://en.wikipedia.org/wiki/Certificate_signing_request
    fn wikipedia_csr() {
        // let data = include_bytes!("../../test-data/csr/wikipedia-csr.pem");
        let data = include_bytes!("../../test-data/csr/test.csr");

        let mut pems: Vec<_> = extract_raw_pems(data)
            .flatten()
            .map(Pem::try_from)
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(pems.len(), 1);
        let parsed = pems.pop().unwrap().parsed;

        let csr = parsed.into_cert_req().unwrap();
        let simple_csr = crate::x509::SimpleCsr::from(csr);
        println!("{}", serde_json::to_string_pretty(&simple_csr).unwrap());
        // assert_eq!(subject, "C=EN, ST=none, L=none, O=Wikipedia, OU=none, CN=*.wikipedia.org/emailAddress=none@none.com");

        std::mem::forget(simple_csr);
    }
}
