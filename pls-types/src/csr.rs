use boring::x509::X509Req;

use crate::{sans::Sans, subject::Subject, util::Hex};

pub struct Csr {
    pub subject: Subject,
    pub subject_alt_name: Sans,
    pub der: Hex,
}

impl Csr {
    pub fn from_der(der: &[u8]) -> Result<Self, anyhow::Error> {
        let req = X509Req::from_der(der)?;
        Ok(Self::from_req(&req))
    }

    pub fn from_req(req: &X509Req) -> Self {
        let subject = Subject::from_subject(req.subject_name());
        let subject_alt_name = Sans::from_subject_alt_names(&req.subject_alt_names().unwrap());
        let der = Hex::from(req.to_der().unwrap());
        Self {
            subject,
            subject_alt_name,
            der,
        }
    }
}
