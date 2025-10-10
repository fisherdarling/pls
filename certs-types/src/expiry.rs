use anyhow::Context;
use boring::x509::X509;
use jiff::{Timestamp, tz::Offset};
use serde::Serialize;

#[derive(Default, Debug, Clone, Serialize)]
pub struct Expiry {
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl Expiry {
    pub fn from_cert(cert: &X509) -> anyhow::Result<Self> {
        Ok(Self {
            not_before: parse_asn1_time_print(cert.not_before())?,
            not_after: parse_asn1_time_print(cert.not_after())?,
        })
    }
}

fn parse_asn1_time_print(time: &boring::asn1::Asn1TimeRef) -> anyhow::Result<Timestamp> {
    let ts = time.to_string().replace(" GMT", " +0000");

    let mut bdt = jiff::fmt::strtime::parse("%h %d %T %Y %z", &ts)
        .with_context(|| format!("parsing ASN1 time: {}", time.to_string()))?;
    bdt.set_offset(Some(Offset::ZERO));

    match bdt.to_timestamp() {
        Ok(timestamp) => Ok(timestamp),
        Err(error) => {
            if bdt.year() == Some(9999) {
                Ok(Timestamp::MAX)
            } else {
                Err(error.into())
            }
        }
    }
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
