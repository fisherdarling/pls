use std::{collections::HashSet, path::PathBuf};

use anyhow::Context as _;
use certs_scanner::{ScanConfig, ScanResult};
use certs_types::Timestamp;
use clap::Parser;
use simple_progress::ProgressBar;

use crate::context::Ctx;

#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Paths to scan for certificates. If not provided, the default roots for the system will be used.
    roots: Option<Vec<PathBuf>>,
}

impl ScanArgs {
    pub fn run(self, ctx: &Ctx) -> anyhow::Result<()> {
        let mut settings = ctx.settings().clone();

        if let Some(roots) = self.roots {
            settings.scanning.roots = canonicalize_roots(roots)?;
        }

        let (files_rx, files_seen_rx) = certs_scanner::scan(ScanConfig::from(&settings));

        let mut files_seen = 0;
        let mut buffer = Vec::new();

        let mut index = certs_scan_index::CertIndex::new();
        let mut seen_serials = HashSet::new();

        let pb = ProgressBar::new("{elapsed} scanning {rate} files/s. Total {total}");

        loop {
            let _ = files_seen_rx.drain_into(&mut buffer);
            let total_updates = buffer.iter().sum::<usize>();
            buffer.clear();

            files_seen += total_updates;
            pb.inc_many(total_updates);

            while let Ok(Some((entry, scan_result))) = files_rx.try_recv() {
                match scan_result {
                    ScanResult::Cert(cert) => {
                        if seen_serials.insert(cert.serial.clone()) {
                            pb.log(format!("{:?}: {:?}", cert.serial, entry.path()));
                            index.add(cert, entry.path().into());
                        }
                    }
                    _ => (),
                }
            }

            if files_rx.is_terminated() {
                break;
            }
        }

        println!();
        println!("{} certs found in {} files", index.len(), files_seen);
        println!();

        println!("Certs by type:");
        println!("  Leaf: {}", index.len_leaf_certs());
        println!("  Intermediate: {}", index.len_intermediate_certs());
        println!("  Root: {}", index.len_root_certs());

        if let Some(cert) = index.next_expiring(Timestamp::now()) {
            println!();
            println!("Next expiring certificate:");
            println!("  serial: {:?}", cert.cert.serial);
            println!("  sans: {:?}", cert.cert.sans);
            println!("  not after: {:?}", cert.cert.expiry.not_after);
            println!("  fingerprint: {:?}", cert.cert.fingerprints.sha256);

            println!(
                "  path: {}:{}:{}",
                cert.path.display(),
                cert.cert.line(),
                cert.cert.col()
            );
        }

        Ok(())
    }
}

fn canonicalize_roots(roots: Vec<PathBuf>) -> anyhow::Result<Vec<PathBuf>> {
    let mut canonicalized = Vec::new();

    for root in roots {
        let canonicalized_root = root.canonicalize().context("Failed to canonicalize root")?;
        canonicalized.push(canonicalized_root);
    }

    Ok(canonicalized)
}
