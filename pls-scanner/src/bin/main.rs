use std::path::PathBuf;

use pls_scanner::ScanConfig;

fn main() {
    let path = std::env::args().nth(1);

    let mut config = ScanConfig::default();
    if let Some(path) = path {
        config.roots = vec![PathBuf::from(path).canonicalize().unwrap()];
    }

    println!("scanning... {config:?}");
    pls_scanner::scan(config);
}
