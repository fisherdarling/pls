use certs_parser::Parser;

fn main() {
    let path = std::env::args().nth(1).unwrap();

    let data = std::fs::read(path).unwrap();
    let parser = Parser::new(&data);

    for pem in parser.parse() {
        match pem {
            certs_parser::ParsedItem::SpannedParsedPem(spanned_parsed_pem) => {
                println!("{}", spanned_parsed_pem.label());
                println!("{:?}", spanned_parsed_pem.value());
            }
            certs_parser::ParsedItem::DecodeFailedPem(spanned, error) => {
                println!("{:?}", String::from_utf8_lossy(&*spanned.label()));
                println!("{}", error);
            }
        }
    }
}
