use anyhow::Context;
use boring::x509::X509;
use bytes::Bytes;
use serde::Serialize;

use crate::{
    expiry::Expiry,
    id::{Aki, Digests, SerialNumber, Ski},
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
    pub serial: SerialNumber,
    pub ski: Option<Ski>,
    pub aki: Option<Aki>,
    pub signature: Signature,
    pub fingerprints: Digests,
    pub der: Hex,
}

impl Cert {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let cert = X509::from_der(der).context("decoding DER with BoringSSL")?;
        Ok(Self::from_boring(&cert))
    }

    pub fn from_pem(pem: &[u8]) -> anyhow::Result<Self> {
        let cert = X509::from_pem(pem).context("decoding PEM with BoringSSL")?;
        Ok(Self::from_boring(&cert))
    }

    pub fn from_boring(cert: &X509) -> Self {
        Self {
            subject: Subject::from_cert(cert),
            expiry: Expiry::from_cert(cert),
            sans: Sans::from_cert(cert),
            issuer: Issuer::from_cert(cert),
            public_key: CertPublicKey::from_cert(cert),
            serial: SerialNumber::from_cert(cert),
            ski: Ski::from_cert(cert),
            aki: Aki::from_cert(cert),
            signature: Signature::from_cert(cert),
            fingerprints: Digests::from_cert(cert),
            der: Hex::from(cert.to_der().unwrap()),
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
