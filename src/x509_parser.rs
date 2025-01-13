use boring::x509::X509;
use color_eyre::{eyre::eyre, Result};
use memchr::{memchr_iter, memmem};

/// Parse a PEM encoded X509 certificate
pub fn parse_pem(data: &[u8]) -> Result<Vec<X509>> {
    // let Some((begin, end)) = find_cert_boundries_raw(data).next() else {
    //     return Err(eyre!("No PEM certificate found"));
    // };

    find_cert_boundries_raw(data)
        .map(|(begin, end)| {
            let data = clean_cert_lines(&data[begin..=end]);
            X509::from_pem(data.as_bytes())
                .map_err(|e| eyre!("Failed to parse PEM certificate: {}", e))
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
    let begin_marker = b"-----BEGIN CERTIFICATE-----";
    let end_marker = b"-----END CERTIFICATE-----";

    let begin_markers = memmem::find_iter(data, begin_marker);
    begin_markers.filter_map(move |begin| {
        let end = memmem::find(&data[begin..], end_marker)?;
        Some((begin, begin + end + end_marker.len()))
    })
}

fn clean_cert_lines(data: &[u8]) -> String {
    let mut start = 0;
    let mut cert = String::with_capacity(data.len());
    let lines = memchr_iter(b'\n', data);

    for line_idx in lines {
        // todo: implement internal whitespace collapsing, e.g. removing
        // the whitespace in `MIIDfzCCAwSgAwIBAgI    LdBXBHQEv\n`

        let line = String::from_utf8_lossy(&data[start..line_idx]);
        cert.push_str(line.trim());
        cert.push('\n');
        start = line_idx + 1;
    }

    cert
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_pem() {
        let data = include_bytes!("../certs/lan-fish.pem");

        let marker = find_cert_boundries_raw(data).next().unwrap();
        assert_eq!(marker, (0, data.len() - 1)); // -1 for the newline
        parse_pem(data).unwrap();
    }

    #[test]
    fn indented_pem() {
        let data = include_bytes!("../certs/indented.pem");
        parse_pem(data).unwrap();
    }
}
