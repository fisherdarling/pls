use boring::{base64, x509::X509};
use color_eyre::{eyre::eyre, Result};
use memchr::memmem;

const BEGIN_MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
const END_MARKER: &[u8] = b"-----END CERTIFICATE-----";

/// Parse a PEM encoded X509 certificate
pub fn parse_pem(data: &[u8]) -> Result<Vec<X509>> {
    find_cert_boundries_raw(data)
        .map(|(begin, end)| {
            let cert_base64 =
                clean_cert_lines(&data[begin + BEGIN_MARKER.len()..=end - END_MARKER.len() - 1]);
            let cert = base64::decode_block(&cert_base64)
                .map_err(|e| eyre!("Failed to decode base64 certificate: {}", e))?;
            X509::from_der(&cert).map_err(|e| eyre!("Failed to parse PEM certificate: {}", e))
        })
        .collect()
}

/// Parse a DER encoded X509 certificate
pub fn parse_der(data: &[u8]) -> Result<Vec<X509>> {
    Ok(vec![X509::from_der(data).map_err(|e| {
        eyre!("Failed to parse DER certificate: {}", e)
    })?])
}

/// Attempt to parse certificate data as either PEM or DER
pub fn parse_auto(data: &[u8]) -> Result<Vec<X509>> {
    parse_pem(data).or_else(|_| parse_der(data))
}

fn find_cert_boundries_raw(data: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let begin_markers = memmem::find_iter(data, BEGIN_MARKER);
    begin_markers.filter_map(move |begin| {
        let end = memmem::find(&data[begin..], END_MARKER)?;
        Some((begin, begin + end + END_MARKER.len()))
    })
}

fn clean_cert_lines(data: &[u8]) -> String {
    let cert = String::from_iter(
        data.iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .map(char::from),
    );

    cert.replace("\\n", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_pem() {
        let data = include_bytes!("../../certs/lan-fish.pem");

        let marker = find_cert_boundries_raw(data).next().unwrap();
        assert_eq!(marker, (0, data.len() - 1)); // -1 for the newline
        let certs = parse_pem(data).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn indented_pem() {
        let data = include_bytes!("../../certs/indented.pem");
        let certs = parse_pem(data).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn json_certs() {
        let certs = include_bytes!("../../certs/pems.json");
        let certs = parse_pem(certs).unwrap();

        assert_eq!(certs.len(), 2);
    }
}
