use boring::x509::X509;
use jiff::{Timestamp, Zoned};
use serde::Serialize;

#[derive(Default, Debug, Clone, Serialize)]
pub struct Expiry {
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl Expiry {
    pub fn from_cert(cert: &X509) -> Self {
        Self {
            not_before: parse_asn1_time_print(cert.not_before()),
            not_after: parse_asn1_time_print(cert.not_after()),
        }
    }
}

fn parse_asn1_time_print(time: &boring::asn1::Asn1TimeRef) -> Timestamp {
    let ts = time.to_string().replace(" GMT", " +0000");

    jiff::fmt::strtime::parse("%h %d %T %Y %z", &ts)
        .unwrap()
        .to_zoned()
        .unwrap()
        .timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_expiry() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let expiry = Expiry::from_cert(&cert);
        insta::assert_debug_snapshot!(expiry);
    }
}
