use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use boring::{
    stack::Stack,
    x509::{GeneralName, X509},
};
use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Sans {
    pub dns: Arc<[String]>,
    pub ip: Arc<[IpAddr]>,
    pub email: Arc<[String]>,
    pub uri: Arc<[String]>,
}

impl Sans {
    pub fn from_cert(cert: &X509) -> Self {
        Self::from_subject_alt_names(&cert.subject_alt_names())
    }

    pub fn from_subject_alt_names(sans: &Option<Stack<GeneralName>>) -> Self {
        let Some(sans) = sans else {
            return Self::default();
        };

        let mut dns = Vec::new();
        let mut ip = Vec::new();
        let mut email = Vec::new();
        let mut uri = Vec::new();

        for san in sans.iter() {
            if let Some(value) = san.dnsname() {
                dns.push(value.to_string());
            } else if let Some(value) = san.ipaddress() {
                if let Ok(slice) = <[u8; 4]>::try_from(value) {
                    ip.push(IpAddr::V4(Ipv4Addr::new(
                        slice[0], slice[1], slice[2], slice[3],
                    )));
                } else if let Ok(slice) = <[u8; 16]>::try_from(value) {
                    ip.push(IpAddr::V6(Ipv6Addr::from(slice)));
                }
            } else if let Some(value) = san.email() {
                email.push(value.to_string());
            } else if let Some(value) = san.uri() {
                uri.push(value.to_string());
            }
        }

        Self {
            dns: Arc::from(dns),
            ip: Arc::from(ip),
            email: Arc::from(email),
            uri: Arc::from(uri),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sans() {
        let cert = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let cert = X509::from_pem(cert).unwrap();
        let sans = Sans::from_cert(&cert);
        insta::assert_debug_snapshot!(sans);
    }
}
