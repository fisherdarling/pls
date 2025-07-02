use anyhow::Context;
use boring::x509::X509Req;

use crate::{sans::Sans, subject::Subject, util::Hex};

#[derive(Debug)]
pub struct Csr {
    pub subject: Subject,
    pub subject_alt_name: Sans,
    pub der: Hex,
    // todo: signature
}

impl Csr {
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let req = X509Req::from_der(der)?;
        Self::from_req(&req)
    }

    pub fn from_req(req: &X509Req) -> anyhow::Result<Self> {
        let subject = Subject::from_subject(req.subject_name());
        let subject_alt_names = req
            .subject_alt_names()
            .context("getting subject alt names")?;
        let subject_alt_name = Sans::from_subject_alt_names(&subject_alt_names);

        // let subject_alt_name = match req.subject_alt_names() {
        //     Ok(sans) => Sans::from_subject_alt_names(&sans),
        //     Err(err) => {
        //         println!("failed to get subject alt name: {err}");
        //         Sans::default()
        //     }
        // };

        let der = Hex::from(req.to_der().unwrap());
        Ok(Self {
            subject,
            subject_alt_name,
            der,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weird_curl_csr() {
        let csr = b"-----BEGIN CERTIFICATE REQUEST-----
MIICnDCCAYQCAQAwVzELMAkGA1UEBhMCTk4xMTAvBgNVBAoMKEVkZWwgQ3VybCBB
cmN0aWMgSWxsdWRpdW0gUmVzZWFyY2ggQ2xvdWQxFTATBgNVBAMMDGxvY2FsaG9z
dC5ubjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALWgVmX/Gh2aTfEX
vhTHMv5RoKMiJlls1Qx0qWwmHKaSZh2WDlnLfQUBsDET3NvmgfF5Q4AIN3QuUYK2
h3z9hy390NNCMsmo0czgN3/iPmWS0k39ee3vI9UxL/vvXwNoSWp8qulwI2tDlb1e
0fgWp9XgvX9jRKQsTTQWMhESzt8WpNgGpcvUTM8prGfBgibBC/9Er/OyiTGiEP2l
MvgETmsyHSReg4k9SZw0JFoT3SwLLFyzX778bdu+w8RAbehRv+H+O/AoQiT1aMQu
APohNPDRlD9lUBmNvs8HKghPaHB39hR4RS9w2kcmUXMdu7KT4SN3baBHTjTHr/2p
U0Hq53MCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBt9eE5YhGU2bhKrDvnOlCW
2/5QFLzKYgZQHf3v+bK4DzhPFZSLHkls5oV+MbAms/CdU1t4uA9J63DIlfDEe302
k5m4NJ/v4NvpQtHVheMi6BkK+BQWnV/BVTv85N550wi2BtkxRqtEPyJu6XDbIgPp
nUP9TCVPjgM1/njekHLD2fm8NBFwFaKBLsw2GSSm7mpdwyhOxTdwOHbwpei5xR/9
U0OtS2NJv0KIiZS0GyGoBK2VN6iwUTPBEuxTUNfpRoboknwtY0f0RfRXeYZzAelx
OL7UNvFt1njk4pY8YOAVKqHszWGV46c5XalMQDJpwP7xzc52W+q9x4psx3br4J3u
-----END CERTIFICATE REQUEST-----";

        let req = X509Req::from_pem(csr).unwrap();
        let csr = Csr::from_req(&req).unwrap();
        println!("{:?}", csr);
    }
}
