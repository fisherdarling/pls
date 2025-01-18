use std::{
    fmt::{self, Display, Formatter},
    net::IpAddr,
};

use boring::{
    bn::BigNumContext,
    ec::PointConversionForm,
    nid::Nid,
    pkey::{Id, PKey, Public},
    x509::{
        extension::{ExtendedKeyUsage, KeyUsage},
        X509VerifyResult, X509,
    },
};
use color_eyre::eyre::Result;
use jiff::{Timestamp, Unit, Zoned};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SimpleCert {
    pub subject: Subject,
    pub serial: String,
    pub issuer: Issuer,
    #[serde(flatten)]
    pub validity: Validity,
    pub ski: Option<String>,
    pub aki: Option<String>,
    pub public_key: SimplePublicKey,
    pub key_usage: SimpleKeyUsage,
    pub signature: Signature,
    pub extensions: Extensions,
    pub fingerprints: Fingerprints,
    #[serde(skip)]
    pub _cert: X509,
}

impl SimpleCert {
    pub fn apply_verify_result(&mut self, verify_result: X509VerifyResult) {
        if let Err(err) = verify_result {
            self.validity.valid = Some(false);
            self.validity.verify_result = Some(err.to_string());
        } else {
            self.validity.valid = Some(true);
        }
    }
}

impl From<X509> for SimpleCert {
    fn from(cert: X509) -> Self {
        let subject = Subject::from(&cert);
        let issuer = Issuer::from(&cert);
        let validity = Validity::from(&cert);
        let public_key = cert.public_key().unwrap();
        let extensions = Extensions::default();

        SimpleCert {
            subject,
            ski: cert.subject_key_id().map(|ski| hex::encode(ski.as_slice())),
            aki: cert
                .authority_key_id()
                .map(|ski| hex::encode(ski.as_slice())),
            issuer,
            public_key: SimplePublicKey::from(public_key),
            serial: cert
                .serial_number()
                .to_bn()
                .unwrap()
                .to_hex_str()
                .unwrap()
                .to_string(),
            validity,
            signature: Signature {
                algorithm: cert
                    .signature_algorithm()
                    .object()
                    .nid()
                    .short_name()
                    .unwrap()
                    .to_string(),
                value: hex::encode(cert.signature().as_slice()),
            },
            key_usage: (cert.key_usage(), cert.extended_key_usage()).into(),
            extensions,
            fingerprints: Fingerprints {
                sha256: hex::encode(cert.digest(boring::hash::MessageDigest::sha256()).unwrap()),
                sha1: hex::encode(cert.digest(boring::hash::MessageDigest::sha1()).unwrap()),
                md5: hex::encode(cert.digest(boring::hash::MessageDigest::md5()).unwrap()),
            },
            _cert: cert,
        }
    }
}

impl Default for SimpleCert {
    fn default() -> Self {
        Self {
            subject: Default::default(),
            serial: Default::default(),
            issuer: Default::default(),
            validity: Default::default(),
            ski: Default::default(),
            aki: Default::default(),
            public_key: Default::default(),
            key_usage: Default::default(),
            signature: Default::default(),
            extensions: Default::default(),
            fingerprints: Default::default(),
            _cert: X509::builder().unwrap().build(),
        }
    }
}

impl Display for SimpleCert {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let pretty = serde_json::to_string_pretty(self).unwrap();
        write!(f, "{pretty}")
    }
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct Subject {
    pub name: String,
    pub ski: Option<String>,
    pub sans: Sans,
}

impl From<&X509> for Subject {
    fn from(cert: &X509) -> Self {
        let san_vec: Vec<_> = cert
            .subject_alt_names()
            .map(|stack| stack.into_iter().map(San::from).collect())
            .unwrap_or_default();
        let sans = Sans::from(san_vec);

        Subject {
            name: cert.subject_name().print_ex(0).unwrap(),
            ski: cert.subject_key_id().map(|ski| hex::encode(ski.as_slice())),
            sans,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct Issuer {
    pub name: String,
    pub aki: Option<String>,
}

impl From<&X509> for Issuer {
    fn from(cert: &X509) -> Self {
        Issuer {
            name: cert.issuer_name().print_ex(0).unwrap(),
            aki: cert
                .authority_key_id()
                .map(|aki| hex::encode(aki.as_slice())),
        }
    }
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct Fingerprints {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimplePublicKey {
    pub bits: usize,
    #[serde(flatten)]
    pub curve: SimpleCruve,
    #[serde(flatten)]
    pub kind: SimplePublicKeyKind,
}

impl Default for SimplePublicKey {
    fn default() -> Self {
        SimplePublicKey {
            bits: 0,
            curve: SimpleCruve::new(Nid::RSA),
            kind: SimplePublicKeyKind::RSA {
                size: 0,
                modulus: "".to_string(),
                exponent: "".to_string(),
            },
        }
    }
}

impl From<PKey<Public>> for SimplePublicKey {
    fn from(key: PKey<Public>) -> Self {
        let kind = match key.id() {
            Id::RSA => {
                let rsa = key.rsa().unwrap();
                SimplePublicKeyKind::RSA {
                    size: (rsa.size() as usize * 8),
                    modulus: hex::encode(rsa.n().to_vec()),
                    exponent: rsa.e().to_dec_str().unwrap().to_string().parse().unwrap(),
                }
            }
            Id::DSA => {
                let dsa = key.dsa().unwrap();
                SimplePublicKeyKind::DSA {
                    size: (dsa.size() as usize * 8),
                    p: dsa.p().to_hex_str().unwrap().to_string(),
                    q: dsa.q().to_hex_str().unwrap().to_string(),
                    g: dsa.g().to_hex_str().unwrap().to_string(),
                    key: dsa.pub_key().to_hex_str().unwrap().to_string(),
                }
            }
            Id::EC => {
                let ec = key.ec_key().unwrap();
                let mut bignum = BigNumContext::new().unwrap();
                SimplePublicKeyKind::EC {
                    // pub_key: hex::encode(ec.public_key().to_bytes(group, form, ctx)),
                    group: ec.group().curve_name(),
                    key: hex::encode(
                        ec.public_key()
                            .to_bytes(ec.group(), PointConversionForm::COMPRESSED, &mut bignum)
                            .unwrap(),
                    ),
                }
            }
            Id::ED25519 => {
                let ec = key.ec_key().unwrap();
                let mut bignum = BigNumContext::new().unwrap();
                SimplePublicKeyKind::Ed25519 {
                    // pub_key: hex::encode(ec.public_key().to_bytes(group, form, ctx)),
                    pub_key: hex::encode(
                        ec.public_key()
                            .to_bytes(ec.group(), PointConversionForm::COMPRESSED, &mut bignum)
                            .unwrap(),
                    ),
                }
            }
            Id::ED448 => {
                let ec = key.ec_key().unwrap();
                let mut bignum = BigNumContext::new().unwrap();
                SimplePublicKeyKind::Ed448 {
                    // pub_key: hex::encode(ec.public_key().to_bytes(group, form, ctx)),
                    pub_key: hex::encode(
                        ec.public_key()
                            .to_bytes(ec.group(), PointConversionForm::COMPRESSED, &mut bignum)
                            .unwrap(),
                    ),
                }
            }
            _ => unreachable!(),
        };

        SimplePublicKey {
            bits: key.bits() as usize,
            curve: SimpleCruve::new(key.nid()),
            kind,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum SimplePublicKeyKind {
    RSA {
        size: usize,
        modulus: String,
        exponent: String,
    },
    DSA {
        size: usize,
        p: String,
        q: String,
        g: String,
        key: String,
    },
    EC {
        #[serde(serialize_with = "serialize_ec_group")]
        group: Option<Nid>,
        key: String,
    },
    Ed25519 {
        pub_key: String,
    },
    Ed448 {
        pub_key: String,
    },
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct Signature {
    pub algorithm: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct Validity {
    pub not_before: Timestamp,
    pub not_after: Timestamp,
    pub expires_in: i64,
    pub valid_in: i64,
    pub valid: Option<bool>,
    pub verify_result: Option<String>,
}

impl From<&X509> for Validity {
    fn from(cert: &X509) -> Self {
        let not_before = parse_asn1_time_print(cert.not_before()).timestamp();
        let not_after = parse_asn1_time_print(cert.not_after()).timestamp();
        let now = Timestamp::now();

        Validity {
            not_before,
            not_after,
            expires_in: (not_after - now).total(Unit::Second).unwrap() as i64,
            valid_in: (not_before - now).total(Unit::Second).unwrap() as i64,
            valid: None,
            verify_result: None,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct Sans {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub email: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uri: Vec<String>,
}

impl From<Vec<San>> for Sans {
    fn from(sans: Vec<San>) -> Self {
        let mut dns = Vec::new();
        let mut ip = Vec::new();
        let mut email = Vec::new();
        let mut uri = Vec::new();

        for san in sans {
            match san {
                San::Dns(value) => dns.push(value),
                San::Ip(value) => ip.push(value),
                San::Email(value) => email.push(value),
                San::Uri(value) => uri.push(value),
            }
        }

        Sans {
            dns,
            ip,
            email,
            uri,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum San {
    Dns(String),
    Ip(IpAddr),
    Email(String),
    Uri(String),
}

impl From<boring::x509::GeneralName> for San {
    fn from(value: boring::x509::GeneralName) -> Self {
        if let Some(dns) = value.dnsname() {
            San::Dns(dns.to_string())
        } else if let Some(ip) = value.ipaddress() {
            San::Ip(if ip.len() == 4 {
                IpAddr::from(<[u8; 4]>::try_from(ip).unwrap())
            } else {
                IpAddr::from(<[u8; 16]>::try_from(ip).unwrap())
            })
        } else if let Some(email) = value.email() {
            San::Email(email.to_string())
        } else if let Some(uri) = value.uri() {
            San::Uri(uri.to_string())
        } else {
            unreachable!()
        }
    }
}

// impl From<GeneralName<'_>> for San {
//     fn from(value: GeneralName<'_>) -> Self {
//         match value {
//             GeneralName::RFC822Name(email) => San::Email(email.to_string()),
//             GeneralName::DNSName(host) => San::Dns(host.to_string()),
//             GeneralName::URI(uri) => San::Uri(uri.to_string()),
//             GeneralName::IPAddress(ip) => San::Ip(if ip.len() == 4 {
//                 IpAddr::from(<[u8; 4]>::try_from(ip).unwrap())
//             } else if ip.len() == 16 {
//                 IpAddr::from(<[u8; 16]>::try_from(ip).unwrap())
//             } else {
//                 panic!()
//             }),
//             _ => panic!(),
//         }
//     }
// }

#[derive(Default, Debug, Clone, Serialize)]
pub struct Extensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_constraints: Option<BasicConstraints>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<usize>,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct SimpleKeyUsage {
    pub critical: bool,
    pub digital_signature: bool,
    pub content_commitment: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
    pub extended: SimpleExtendedKeyUsage,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct SimpleExtendedKeyUsage {
    critical: bool,
    server_auth: bool,
    client_auth: bool,
    code_signing: bool,
    email_protection: bool,
    time_stamping: bool,
    ocsp_signing: bool,
    custom: Vec<String>,
}

impl From<(KeyUsage, ExtendedKeyUsage)> for SimpleKeyUsage {
    fn from((key_usage, ext_key_usage): (KeyUsage, ExtendedKeyUsage)) -> Self {
        SimpleKeyUsage {
            critical: key_usage.critical,
            digital_signature: key_usage.digital_signature,
            content_commitment: key_usage.non_repudiation,
            key_encipherment: key_usage.key_encipherment,
            data_encipherment: key_usage.data_encipherment,
            key_agreement: key_usage.key_agreement,
            key_cert_sign: key_usage.key_cert_sign,
            crl_sign: key_usage.crl_sign,
            encipher_only: key_usage.encipher_only,
            decipher_only: key_usage.decipher_only,
            extended: SimpleExtendedKeyUsage {
                critical: ext_key_usage.critical,
                server_auth: ext_key_usage.server_auth,
                client_auth: ext_key_usage.client_auth,
                code_signing: ext_key_usage.code_signing,
                email_protection: ext_key_usage.email_protection,
                time_stamping: ext_key_usage.time_stamping,
                ocsp_signing: ext_key_usage.ocsp_signing,
                custom: ext_key_usage.items.clone(),
            },
        }
    }
}

fn parse_asn1_time_print(time: &boring::asn1::Asn1TimeRef) -> Zoned {
    let ts = time.to_string().replace(" GMT", " +0000");

    jiff::fmt::strtime::parse("%h %d %T %Y %z", &ts)
        .unwrap()
        .to_zoned()
        .unwrap()
}

#[derive(Clone, Serialize)]
pub struct SimpleCruve {
    #[serde(serialize_with = "serialize_nid")]
    curve: Nid,
}

impl Default for SimpleCruve {
    fn default() -> Self {
        SimpleCruve { curve: Nid::UNDEF }
    }
}

impl std::fmt::Debug for SimpleCruve {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.curve.long_name().unwrap())
    }
}

impl SimpleCruve {
    pub fn new(nid: Nid) -> Self {
        Self { curve: nid }
    }

    pub fn nid(&self) -> Nid {
        self.curve
    }
}

fn serialize_nid<S>(nid: &Nid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(nid.long_name().unwrap())
}

fn serialize_ec_group<S>(group: &Option<Nid>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match group {
        Some(group) => serialize_nid(group, serializer),
        None => serializer.serialize_none(),
    }
}
