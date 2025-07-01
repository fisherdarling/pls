use std::sync::Arc;

use boring::{
    nid::Nid,
    x509::{X509, X509NameRef},
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject {
    pub common_name: Option<Arc<str>>,
    pub organization: Option<Arc<str>>,
    pub organization_unit: Option<Arc<str>>,
    pub country: Option<Arc<str>>,
    pub state: Option<Arc<str>>,
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();

        if let Some(country) = &self.country {
            parts.push(format!("C={}", country.as_ref()));
        }

        if let Some(state) = &self.state {
            parts.push(format!("ST={}", state.as_ref()));
        }

        if let Some(organization) = &self.organization {
            parts.push(format!("O={}", organization.as_ref()));
        }

        if let Some(organization_unit) = &self.organization_unit {
            parts.push(format!("OU={}", organization_unit.as_ref()));
        }

        if let Some(common_name) = &self.common_name {
            parts.push(format!("CN={}", common_name.as_ref()));
        }

        write!(f, "{}", parts.join(", "))?;

        Ok(())
    }
}

impl Subject {
    pub fn from_cert(cert: &X509) -> Self {
        Self::from_subject(cert.subject_name())
    }

    pub fn from_subject(subject: &X509NameRef) -> Self {
        let mut common_name = None;
        let mut organization = None;
        let mut organization_unit = None;
        let mut country = None;
        let mut state = None;

        for entry in subject.entries() {
            let Ok(value) = entry.data().as_utf8() else {
                continue;
            };

            if entry.object().nid() == Nid::COMMONNAME {
                common_name = Some(Arc::from(value.as_ref()));
            } else if entry.object().nid() == Nid::ORGANIZATIONNAME {
                organization = Some(Arc::from(value.as_ref()));
            } else if entry.object().nid() == Nid::ORGANIZATIONALUNITNAME {
                organization_unit = Some(Arc::from(value.as_ref()));
            } else if entry.object().nid() == Nid::COUNTRYNAME {
                country = Some(Arc::from(value.as_ref()));
            } else if entry.object().nid() == Nid::STATEORPROVINCENAME {
                state = Some(Arc::from(value.as_ref()));
            }
        }

        Self {
            common_name,
            organization,
            organization_unit,
            country,
            state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_subject() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let subject = Subject::from_cert(&cert);
        insta::assert_debug_snapshot!(subject); // CN=cloudflare.com
    }
}
