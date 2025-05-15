use boring::x509::X509;
use serde::Serialize;

use crate::subject::Subject;

#[derive(Debug, Clone, Serialize)]
pub struct Issuer {
    pub subject: Subject,
}

impl Issuer {
    pub fn from_cert(cert: &X509) -> Self {
        Self {
            subject: Subject::from_subject(cert.issuer_name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_issuer() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let issuer = Issuer::from_cert(&cert);
        insta::assert_debug_snapshot!(issuer); // CN=cloudflare.com
    }
}
