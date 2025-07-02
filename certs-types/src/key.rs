use anyhow::{Context, bail};
use boring::{
    bn::BigNumContext,
    dh::Dh,
    ec::{EcKey, PointConversionForm},
    pkey::{PKey, Params, Private, Public},
    rsa::Rsa,
    x509::X509,
};
use serde::Serialize;

use crate::{nid::Nid, util::Hex};

#[derive(Debug, Clone, Serialize)]
pub struct CertPublicKey {
    pub usage: KeyUsage,
    pub extended_usage: ExtendedKeyUsage,
    #[serde(flatten)]
    pub key: PublicKey,
    pub spki: Hex,
}

impl CertPublicKey {
    pub fn from_cert(cert: &X509) -> anyhow::Result<Self> {
        let key = PublicKey::from_cert(cert)?;
        let usage = KeyUsage::from_cert(cert);
        let extended_usage = ExtendedKeyUsage::from_cert(cert);
        let spki = Hex::from(cert.public_key().unwrap().public_key_to_der().unwrap());
        Ok(Self {
            key,
            usage,
            extended_usage,
            spki,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum PublicKey {
    Rsa { n: Hex, e: Hex },
    Ec { curve: Nid, point: Hex },
    Ed25519 { key: Hex },
}

impl PublicKey {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let pk = PKey::<Public>::public_key_from_der(der).context("parsing public key")?;
        Self::from_boring(pk)
    }

    pub fn from_cert(cert: &X509) -> anyhow::Result<Self> {
        let pk = cert.public_key().unwrap();
        Self::from_boring(pk)
    }

    pub fn from_boring(pk: PKey<Public>) -> anyhow::Result<Self> {
        if let Ok(rsa) = pk.rsa() {
            Ok(Self::Rsa {
                n: Hex::from(rsa.n().to_vec()),
                e: Hex::from(rsa.e().to_vec()),
            })
        } else if let Ok(ec) = pk.ec_key() {
            let mut ctx = BigNumContext::new().unwrap();
            let group = ec.group();
            let form = PointConversionForm::COMPRESSED;
            let key = ec.public_key().to_bytes(group, form, &mut ctx).unwrap();

            Ok(Self::Ec {
                curve: Nid::from_boring(ec.group().curve_name().unwrap()),
                point: Hex::from(key),
            })
        } else if let Ok(_) = pk.dh() {
            todo!()
        } else if pk.id() == boring::pkey::Id::ED25519 {
            Ok(Self::Ed25519 {
                key: Hex::from(pk.raw_public_ed25519_key().unwrap()),
            })
        } else {
            anyhow::bail!(
                "Unsupported public key type: {:?}: {:?}",
                pk.id(),
                pk.nid().long_name()
            )
        }
    }
}

// pub enum SimplePrivateKeyKind {
//     RSA {
//         size: usize,
//         modulus: String,
//         exponent: String,
//         p: String,
//         q: String,
//         key: String,
//     },
//     DSA {
//         size: usize,
//         p: String,
//         q: String,
//         g: String,
//         pub_key: String,
//         key: String,
//     },
//     EC {
//         #[serde(serialize_with = "serialize_ec_group")]
//         group: Option<Nid>,
//         pub_key: String,
//         key: String,
//     },
//     Ed25519 {
//         pub_key: String,
//         key: String,
//     },
//     Ed448 {
//         pub_key: String,
//         key: String,
//     },
// }

#[derive(Debug)]
pub struct Ed25519PrivateKey {
    key: Hex,
}

#[derive(Debug)]
pub struct EcPrivateKey {
    curve: Nid,
    key: Hex,
}

impl EcPrivateKey {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let key = EcKey::<Private>::private_key_from_der(der).context("parsing EC private key")?;
        Self::from_boring(key)
    }

    pub fn from_boring(key: EcKey<Private>) -> anyhow::Result<Self> {
        Ok(Self {
            curve: Nid::from_boring(key.group().curve_name().unwrap()),
            key: Hex::from(key.private_key().to_vec()),
        })
    }
}

#[derive(Debug)]
pub enum PrivateKey {
    Ed25519(Ed25519PrivateKey),
    Rsa(RsaPrivateKey),
    Ec(EcPrivateKey),
}

impl PrivateKey {
    pub fn from_pem(pem: &[u8]) -> anyhow::Result<Self> {
        let key = PKey::<Private>::private_key_from_pem(pem).context("parsing private key")?;
        Self::from_boring(key)
    }

    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let key = PKey::<Private>::private_key_from_der(der).context("parsing private key")?;
        Self::from_boring(key)
    }

    pub fn from_boring(key: PKey<Private>) -> anyhow::Result<Self> {
        if key.nid() == boring::nid::Nid::ED25519 {
            let key = key.raw_private_ed25519_key().unwrap();
            Ok(Self::Ed25519(Ed25519PrivateKey {
                key: Hex::from(key),
            }))
        } else if let Ok(rsa) = key.rsa() {
            Ok(Self::Rsa(RsaPrivateKey::from_boring(rsa)?))
        } else if let Ok(ec) = key.ec_key() {
            Ok(Self::Ec(EcPrivateKey::from_boring(ec)?))
        } else {
            bail!("Unsupported private key type: {:?}", key.nid().long_name());
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DhParams {
    pub der: Hex,
}

impl DhParams {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let dh = Dh::<Params>::params_from_der(der).context("parsing DH params")?;
        Ok(Self {
            der: Hex::from(dh.params_to_der().context("serializing DH params")?),
        })
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

#[derive(Debug, Clone, Serialize)]
pub struct ExtendedKeyUsage {
    pub critical: bool,
    pub server_auth: bool,
    pub client_auth: bool,
    pub code_signing: bool,
    pub email_protection: bool,
    pub time_stamping: bool,
    pub ocsp_signing: bool,
}

impl ExtendedKeyUsage {
    pub fn from_cert(cert: &X509) -> Self {
        Self::from_boring(&cert.extended_key_usage())
    }

    pub fn from_boring(key_usage: &boring::x509::extension::ExtendedKeyUsage) -> Self {
        Self {
            critical: key_usage.critical,
            server_auth: key_usage.server_auth,
            client_auth: key_usage.client_auth,
            code_signing: key_usage.code_signing,
            email_protection: key_usage.email_protection,
            time_stamping: key_usage.time_stamping,
            ocsp_signing: key_usage.ocsp_signing,
        }
    }
}

#[derive(Debug)]
pub struct RsaPrivateKey {
    pub n: Hex,
    pub e: Hex,
    pub d: Hex,
    pub p: Hex,
    pub q: Hex,
}

impl RsaPrivateKey {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let key = Rsa::<Private>::private_key_from_der(der).context("parsing RSA private key")?;
        Self::from_boring(key)
    }

    pub fn from_boring(key: Rsa<Private>) -> anyhow::Result<Self> {
        let n = Hex::from(key.n().to_vec());
        let e = Hex::from(key.e().to_vec());
        let d = Hex::from(key.d().to_vec());
        let p = Hex::from(key.p().context("getting p")?.to_vec());
        let q = Hex::from(key.q().context("getting q")?.to_vec());

        Ok(Self { n, e, d, p, q })
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
    fn extract_extended_key_usage() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let extended_key_usage = ExtendedKeyUsage::from_cert(&cert);
        insta::assert_debug_snapshot!(extended_key_usage);
    }

    #[test]
    fn extract_public_key() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let public_key = CertPublicKey::from_cert(&cert);
        insta::assert_debug_snapshot!(public_key);
    }

    #[test]
    fn extract_e25519_private_key() {
        let key = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
-----END PRIVATE KEY-----";

        let key = PrivateKey::from_pem(key).unwrap();
        insta::assert_debug_snapshot!(key);
    }
}
