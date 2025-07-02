use std::path::PathBuf;

use certs_scanner::ScanConfig;

fn main() {
    let path = std::env::args().nth(1);

    let mut config = ScanConfig::default();
    if let Some(path) = path {
        config.roots = vec![PathBuf::from(path).canonicalize().unwrap()];
    }

    println!("scanning... {config:?}");
    certs_scanner::scan(config);
}
