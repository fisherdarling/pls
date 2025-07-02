use anyhow::Context;
use boring::x509::X509;
use serde::Serialize;

use crate::{
    expiry::Expiry,
    id::{Aki, Digests, Serial, Ski},
    issuer::Issuer,
    key::CertPublicKey,
    sans::Sans,
    signature::Signature,
    subject::Subject,
    util::Hex,
};

#[derive(Debug, Clone, Serialize)]
pub struct Cert {
    pub subject: Subject,
    pub expiry: Expiry,
    pub sans: Sans,
    pub issuer: Issuer,
    pub public_key: CertPublicKey,
    pub serial: Serial,
    pub ski: Option<Ski>,
    pub aki: Option<Aki>,
    pub basic_constraints: BasicConstraints,
    pub signature: Signature,
    pub fingerprints: Digests,
    pub classification: CertClassification,
    pub der: Hex,
}

impl Cert {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let cert = X509::from_der(der).context("decoding DER with BoringSSL")?;
        Self::from_boring(&cert)
    }

    pub fn from_pem(pem: &[u8]) -> anyhow::Result<Self> {
        let cert = X509::from_pem(pem).context("decoding PEM with BoringSSL")?;
        Self::from_boring(&cert)
    }

    pub fn from_boring(cert: &X509) -> anyhow::Result<Self> {
        let public_key = CertPublicKey::from_cert(cert).context("parsing public key")?;
        let classification =
            CertClassification::from_cert(cert, &public_key).context("parsing classification")?;

        Ok(Self {
            subject: Subject::from_cert(cert),
            expiry: Expiry::from_cert(cert).context("parsing expiry")?,
            sans: Sans::from_cert(cert),
            issuer: Issuer::from_cert(cert),
            public_key: CertPublicKey::from_cert(cert).context("parsing public key")?,
            serial: Serial::from_cert(cert),
            ski: Ski::from_cert(cert),
            aki: Aki::from_cert(cert),
            basic_constraints: BasicConstraints::from_cert(cert)
                .context("parsing basic constraints")?,
            signature: Signature::from_cert(cert),
            fingerprints: Digests::from_cert(cert),
            classification,
            der: Hex::from(cert.to_der().unwrap()),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CertClassification {
    pub is_ca: bool,
    pub authenticates: CertUsage,
    pub depth: CertDepth,
}

impl CertClassification {
    pub fn from_cert(cert: &X509, pubkey: &CertPublicKey) -> anyhow::Result<Self> {
        let is_ca = cert.is_ca();

        let location = if is_ca {
            match cert.issued(&cert) {
                // If the cert is issued by itself, it's a root cert
                Ok(_) => CertDepth::Root,
                Err(_) => CertDepth::Intermediate,
            }
        } else {
            CertDepth::Leaf
        };

        let authenticates = match (
            pubkey.extended_usage.server_auth,
            pubkey.extended_usage.client_auth,
        ) {
            (true, true) => CertUsage::ClientAndServer,
            (true, false) => CertUsage::Server,
            (false, true) => CertUsage::Client,
            (false, false) => {
                if pubkey.usage.key_cert_sign {
                    CertUsage::CA
                } else {
                    CertUsage::Unknown
                }
            }
        };

        Ok(Self {
            is_ca,
            authenticates,
            depth: location,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertUsage {
    Client,
    Server,
    ClientAndServer,
    CA,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CertDepth {
    Leaf,
    Intermediate,
    Root,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicConstraints {
    pub critical: bool,
    pub is_ca: bool,
    pub max_path_length: Option<u32>,
}

impl BasicConstraints {
    pub fn from_cert(cert: &X509) -> anyhow::Result<Self> {
        let basic_constraints = cert
            .basic_constraints()
            .context("getting basic constraints")?
            .context("basic constraints not found")?;
        Ok(Self::from_boring(&basic_constraints))
    }

    pub fn from_boring(basic_constraints: &boring::x509::extension::BasicConstraints) -> Self {
        Self {
            critical: basic_constraints.critical,
            is_ca: basic_constraints.ca,
            max_path_length: basic_constraints.pathlen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cert() {
        let cert =
            Cert::from_pem(include_bytes!("../../test-data/certs/cloudflare.com.pem")).unwrap();
        insta::assert_debug_snapshot!(cert);
    }
}
