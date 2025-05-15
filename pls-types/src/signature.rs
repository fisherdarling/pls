use boring::x509::X509;
use bytes::Bytes;
use serde::Serialize;

use crate::{
    nid::Nid,
    util::{Hex, HexDebug},
};

#[derive(Debug, Clone, Serialize)]
pub struct Signature {
    #[serde(serialize_with = "serialize_nid")]
    pub alg: Nid,
    pub value: Hex,
}

impl Signature {
    pub fn from_cert(cert: &X509) -> Self {
        let signature = cert.signature();
        let alg = cert.signature_algorithm().object().nid();
        Self {
            alg: Nid::from_boring(alg),
            value: Hex::from(signature.as_slice()),
        }
    }
}

fn serialize_nid<T: serde::Serializer>(nid: &Nid, serializer: T) -> Result<T::Ok, T::Error> {
    serializer.serialize_str(nid.long_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_signature() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let signature = Signature::from_cert(&cert);
        insta::assert_debug_snapshot!(signature);
    }
}
