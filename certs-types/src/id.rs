use boring::x509::X509;
use serde::Serialize;

use crate::util::Hex;

/// Serial Number
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Serial(pub Hex);

impl Serial {
    pub fn from_cert(cert: &X509) -> Self {
        let serial_number = cert.serial_number();
        let bytes = serial_number.to_bn().unwrap().to_vec();
        Self(Hex::from(bytes.as_slice()))
    }
}

impl std::fmt::Display for Serial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Authority Key Identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Aki(pub Hex);

impl Aki {
    pub fn from_cert(cert: &X509) -> Option<Self> {
        cert.authority_key_id()
            .map(|aki| Self(Hex::from(aki.as_slice())))
    }
}

/// Subject Key Identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Ski(pub Hex);

impl Ski {
    pub fn from_cert(cert: &X509) -> Option<Self> {
        cert.subject_key_id()
            .map(|ski| Self(Hex::from(ski.as_slice())))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Digests {
    pub md5: Hex,
    pub sha1: Hex,
    pub sha256: Hex,
}

impl Digests {
    pub fn from_cert(cert: &X509) -> Self {
        let md5 = cert.digest(boring::hash::MessageDigest::md5()).unwrap();
        let sha1 = cert.digest(boring::hash::MessageDigest::sha1()).unwrap();
        let sha256 = cert.digest(boring::hash::MessageDigest::sha256()).unwrap();
        Self {
            md5: Hex::from(md5),
            sha1: Hex::from(sha1),
            sha256: Hex::from(sha256),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_serial_number() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let serial_number = Serial::from_cert(&cert);
        insta::assert_debug_snapshot!(serial_number);
    }

    #[test]
    fn extract_aki() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let aki = Aki::from_cert(&cert).unwrap();
        insta::assert_debug_snapshot!(aki);
    }

    #[test]
    fn extract_ski() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let ski = Ski::from_cert(&cert).unwrap();
        insta::assert_debug_snapshot!(ski);
    }

    #[test]
    fn extract_fingerprints() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let fingerprints = Digests::from_cert(&cert);
        insta::assert_debug_snapshot!(fingerprints);
    }
}
