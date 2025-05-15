use pls_parser::Parser;

fn main() {
    let path = std::env::args().nth(1).unwrap();

    let data = std::fs::read(path).unwrap();
    let parser = Parser::new(&data);

    for pem in parser.parse() {
        match pem {
            pls_parser::ParsedItem::SpannedParsedPem(spanned_parsed_pem) => {
                let cert = pls_types::cert::Cert::from_der(spanned_parsed_pem.der()).unwrap();
                println!(
                    "{:?}: {:?}, line={}, col={}\n{:#?}",
                    cert.subject.common_name,
                    cert.ski,
                    spanned_parsed_pem.line(),
                    spanned_parsed_pem.col(),
                    cert
                );
            }
            pls_parser::ParsedItem::DecodeFailedPem(spanned, error) => todo!(),
        }
    }
}
