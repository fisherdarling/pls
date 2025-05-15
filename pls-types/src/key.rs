use boring::{bn::BigNumContext, ec::PointConversionForm, x509::X509};
use bytes::Bytes;
use serde::Serialize;

use crate::{
    nid::Nid,
    util::{Hex, HexDebug},
};

#[derive(Debug, Clone, Serialize)]
pub struct CertPublicKey {
    pub usage: KeyUsage,
    #[serde(flatten)]
    pub key: PublicKey,
    pub spki: Hex,
}

impl CertPublicKey {
    pub fn from_cert(cert: &X509) -> Self {
        let key = PublicKey::from_cert(cert);
        let usage = KeyUsage::from_cert(cert);
        let spki = Hex::from(cert.public_key().unwrap().public_key_to_der().unwrap());
        Self { key, usage, spki }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum PublicKey {
    Rsa { n: Hex, e: Hex },
    Ec { curve: Nid, point: Hex },
}

impl PublicKey {
    pub fn from_cert(cert: &X509) -> Self {
        let pk = cert.public_key().unwrap();

        if let Ok(rsa) = pk.rsa() {
            Self::Rsa {
                n: Hex::from(rsa.n().to_vec()),
                e: Hex::from(rsa.e().to_vec()),
            }
        } else if let Ok(ec) = pk.ec_key() {
            let mut ctx = BigNumContext::new().unwrap();
            let group = ec.group();
            let form = PointConversionForm::COMPRESSED;
            let key = ec.public_key().to_bytes(group, form, &mut ctx).unwrap();

            Self::Ec {
                curve: Nid::from_boring(ec.group().curve_name().unwrap()),
                point: Hex::from(key),
            }
        } else if let Ok(_) = pk.dh() {
            todo!()
        } else {
            panic!("Unsupported public key type");
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyUsage {
    pub critical: bool,
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl KeyUsage {
    pub fn from_cert(cert: &X509) -> Self {
        Self::from_boring(&cert.key_usage())
    }

    pub fn from_boring(key_usage: &boring::x509::extension::KeyUsage) -> Self {
        Self {
            critical: key_usage.critical,
            digital_signature: key_usage.digital_signature,
            non_repudiation: key_usage.non_repudiation,
            key_encipherment: key_usage.key_encipherment,
            data_encipherment: key_usage.data_encipherment,
            key_agreement: key_usage.key_agreement,
            key_cert_sign: key_usage.key_cert_sign,
            crl_sign: key_usage.crl_sign,
            encipher_only: key_usage.encipher_only,
            decipher_only: key_usage.decipher_only,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_key_usage() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let key_usage = KeyUsage::from_cert(&cert);
        insta::assert_debug_snapshot!(key_usage);
    }

    #[test]
    fn extract_public_key() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let public_key = CertPublicKey::from_cert(&cert);
        insta::assert_debug_snapshot!(public_key);
    }
}
