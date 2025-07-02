use std::{
    borrow::Cow,
    cell::LazyCell,
    ops::Range,
    sync::Arc,
};

use anyhow::Context;
use bytes::Bytes;
use regex::bytes::{Regex, RegexBuilder};
use pls_types::Spanned;

thread_local! {
  static PEM_REGEX: Regex = RegexBuilder::new(r"(?P<pem>-----BEGIN (?P<header_label>.*?)-----(?:\n|\\n)?(?P<cert_data>.*?)(?:\n|\\n)?-----END .*?-----)")
  .dot_matches_new_line(true)
  .build().unwrap();
  static NEWLINE_REGEX: Regex = Regex::new(r"\n").unwrap();
  static WHITESPACE_REGEX: Regex = Regex::new(r"\s").unwrap();
  static NOT_B64: regex::Regex = regex::Regex::new(r"[^A-Za-z0-9+/=]").unwrap();
}

pub fn pems<'a>(data: &'a [u8]) -> impl Iterator<Item = Spanned<RawPem<'a>>> {
    PEM_REGEX.with(|re| {
        let captures = get_captures(re, data);
        let newlines = LazyCell::new(|| newlines(data));

        captures
            .into_iter()
            .map(move |(pem, header_label, cert_data)| {
                let (pem_line, pem_col) = determine_line_and_column(&newlines, pem.start());
                let (header_label_line, header_label_col) =
                    determine_line_and_column(&newlines, header_label.start());
                let (cert_data_line, cert_data_col) =
                    determine_line_and_column(&newlines, cert_data.start());

                let label = Spanned::new(
                    header_label.as_bytes(),
                    header_label.range(),
                    header_label_line,
                    header_label_col,
                );

                let cert_data = Spanned::new(
                    cert_data.as_bytes(),
                    cert_data.range(),
                    cert_data_line,
                    cert_data_col,
                );

                Spanned::new(
                    RawPem {
                        label,
                        cert_data,
                        raw_pem: Spanned::new(
                            pem.as_bytes(),
                            pem.range(),
                            pem_line,
                            pem_col,
                        ),
                    },
                    pem.range(),
                    pem_line,
                    pem_col,
                )
            })
    })
}

fn get_captures<'a>(
    re: &Regex,
    data: &'a [u8],
) -> Vec<(
    regex::bytes::Match<'a>,
    regex::bytes::Match<'a>,
    regex::bytes::Match<'a>,
)> {
    re.captures_iter(data)
        .map(move |capture| {
            (
                capture.get(1).unwrap(),
                capture.get(2).unwrap(),
                capture.get(3).unwrap(),
            )
        })
        .collect()
}

fn determine_line_and_column(newlines: &[Range<usize>], index: usize) -> (usize, usize) {
    // +1 because humans 1-index lines
    match newlines.binary_search_by(|range| range.end.cmp(&index)) {
        // we're on a boundry
        Ok(idx) => (idx + 1 + 1, 0), // +1 for the next line, +1 for 1-indexing
        // we're before the first newline
        Err(0) => (1, index),
        // we're in the middle of a line
        Err(idx) => (idx + 1, index - newlines[idx - 1].end),
    }
}

fn newlines<'a>(data: &'a [u8]) -> Vec<Range<usize>> {
    NEWLINE_REGEX.with(|re| re.find_iter(data).map(|c| c.range()).collect())
}

#[derive(Debug)]
pub struct RawPem<'a> {
    label: Spanned<&'a [u8]>,
    cert_data: Spanned<&'a [u8]>,
    raw_pem: Spanned<&'a [u8]>,
}

impl RawPem<'_> {
    pub fn label(&self) -> &Spanned<&[u8]> {
        &self.label
    }

    pub fn raw_pem(&self) -> &[u8] {
        &self.raw_pem
    }

    pub fn cert_data(&self) -> &Spanned<&[u8]> {
        &self.cert_data
    }

    pub fn decode(&self) -> anyhow::Result<DecodedRawPem> {
        let label = std::str::from_utf8(self.label.data()).context("utf8 decoding cert label")?;

        let str_cert_data =
            std::str::from_utf8(self.cert_data.data()).context("utf8 decoding cert data")?;
        let unescaped_cert_data = escape8259::unescape(str_cert_data)
            .context("unescaping cert data")
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed(str_cert_data));

        let cleaned_b64_cert_data = NOT_B64.with(|re| re.replace_all(&unescaped_cert_data, ""));
        let decoded_cert_data = boring::base64::decode_block(&cleaned_b64_cert_data)
            .context("base64 decoding cert data")?;

        let cert_data = Bytes::from(decoded_cert_data);

        Ok(DecodedRawPem {
            label: Spanned::new(
                Arc::from(label),
                self.label.span(),
                self.label.line(),
                self.label.col(),
            ),
            decoded_cert_data: Spanned::new(
                cert_data,
                self.cert_data.span(),
                self.cert_data.line(),
                self.cert_data.col(),
            ),
        })
    }
}

#[derive(Debug)]
pub struct DecodedRawPem {
    label: Spanned<Arc<str>>,
    decoded_cert_data: Spanned<Bytes>,
}

impl DecodedRawPem {
    pub fn label(&self) -> &Spanned<Arc<str>> {
        &self.label
    }

    pub fn der(&self) -> &Spanned<Bytes> {
        &self.decoded_cert_data
    }
}


#[cfg(test)]
mod tests {
    use super::{determine_line_and_column, newlines};
    use crate::lexer::pems;

    #[test]
    fn test_newlines() {
        let data = b"Hello\nWorld\r\n";
        let newlines = newlines(data);

        assert_eq!(&data[newlines[0].clone()], b"\n");
        assert_eq!(&data[newlines[1].clone()], b"\r\n");
    }

    #[test]
    fn test_determine_column_simple() {
        let data = b"\nA";
        let newlines = newlines(data);
        assert_eq!(determine_line_and_column(&newlines, 1), (1, 0));
    }

    #[test]
    fn test_determine_column_complex() {
        let data = b"Hello\nWorld\r\n";
        let newlines = newlines(data);
        assert_eq!(determine_line_and_column(&newlines, 0), (1, 0));
        assert_eq!(determine_line_and_column(&newlines, 1), (1, 1));
        assert_eq!(determine_line_and_column(&newlines, 2), (1, 2));
        assert_eq!(determine_line_and_column(&newlines, 3), (1, 3));
        assert_eq!(determine_line_and_column(&newlines, 4), (1, 4));
        assert_eq!(determine_line_and_column(&newlines, 5), (1, 5));
        assert_eq!(determine_line_and_column(&newlines, 6), (2, 0));
        assert_eq!(determine_line_and_column(&newlines, 7), (2, 1));
        assert_eq!(determine_line_and_column(&newlines, 8), (2, 2));
        assert_eq!(determine_line_and_column(&newlines, 9), (2, 3));
        assert_eq!(determine_line_and_column(&newlines, 10), (2, 4));
        assert_eq!(determine_line_and_column(&newlines, 11), (2, 5));
    }

    #[test]
    fn test_pems() {
        let data =
            b"    \n    -----BEGIN CERTIFICATE-----\nHello, World!\nAnd goodbye!\n-----END CERTIFICATE-----";

        let pem = pems(data).next().unwrap();
        assert_eq!(pem.span(), 9..89);
        assert_eq!(pem.line(), 2);
        assert_eq!(pem.col(), 4);

        let label = pem.label();
        assert_eq!(label.span(), 20..31);
        assert_eq!(label.line(), 2);
        assert_eq!(label.col(), 15);

        let data = pem.cert_data();
        assert_eq!(data.span(), 37..63);
        assert_eq!(data.line(), 3);
        assert_eq!(data.col(), 0);
    }

    #[test]
    fn test_json_pem() {
        let data =
            br#""\"-----BEGIN CERTIFICATE-----\\nHello, World!\\nAnd goodbye!\\n-----END CERTIFICATE-----\"""#;

        let pem = pems(data).next().unwrap();
        assert_eq!(pem.span(), 3..89);
        assert_eq!(pem.line(), 1);
        assert_eq!(pem.col(), 3);
        assert_eq!(pem.raw_pem(), br"-----BEGIN CERTIFICATE-----\\nHello, World!\\nAnd goodbye!\\n-----END CERTIFICATE-----");

        let label = pem.label();
        assert_eq!(label.span(), 14..25);
        assert_eq!(label.line(), 1);
        assert_eq!(label.col(), 14);
        assert_eq!(label.data(), b"CERTIFICATE");

        let data = pem.cert_data();
        assert_eq!(data.span(), 30..62);
        assert_eq!(data.line(), 1);
        assert_eq!(data.col(), 30);
        assert_eq!(data.data(), br"\\nHello, World!\\nAnd goodbye!\");
    }

    #[test]
    fn test_decode_pem() {
        let data = include_bytes!("../../test-data/certs/cloudflare.com.pem");
        let pem = pems(data).next().unwrap();
        let decoded = pem.decode().unwrap();
        assert_eq!(&**decoded.label.data(), "CERTIFICATE");
        assert_eq!(decoded.decoded_cert_data.data().len(), 1017);
    }
}
