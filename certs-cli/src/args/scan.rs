use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
};

use anyhow::Context as _;
use certs_scanner::{ScanConfig, ScanResult};
use certs_types::{
    cert::{Cert, CertWithPaths},
    util::Hex,
    Spanned, SpannedPath, Timestamp,
};
use clap::Parser;
use foundations::reexports_for_macros::serde::Serialize;
use jiff::{
    civil::{Date, DateTime},
    SpanArithmetic, SpanRound, Unit, Zoned,
};
use simple_progress::ProgressBar;

use crate::context::Ctx;

/// Scan a directory and emit all certificates. If `--expires-in` is used, only certificates
/// which expire in the given amount of time will be emitted.
#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Paths to scan for certificates. If not provided, the default roots for the system will be used.
    roots: Option<Vec<PathBuf>>,
    /// Emit certificates if they expires in the given amount of time. E.g. to alert if a certificate expires in one week, use `1w` or `7d`.
    ///
    /// Supports [jiffy's span format](https://docs.rs/jiff/latest/jiff/struct.Span.html#parsing-and-printing).
    #[clap(long)]
    expires_in: Option<String>,
}

impl ScanArgs {
    pub fn run(self, ctx: &Ctx) -> anyhow::Result<()> {
        let mut settings = ctx.settings().clone();

        let expires_in: Option<jiff::Span> = self
            .expires_in
            .as_deref()
            .map(FromStr::from_str)
            .transpose()
            .context("parsing `--expires-in` time expression")?;

        if let Some(roots) = self.roots {
            settings.scanning.roots = canonicalize_roots(roots)?;
        }

        let (files_rx, files_seen_rx) = certs_scanner::scan(ScanConfig::from(&settings));

        let mut files_seen = 0;
        let mut buffer = Vec::new();

        let mut index = CertIndex::default();

        // let pb = ProgressBar::new("{elapsed} scanning {rate} files/s. Total {total}");

        loop {
            let _ = files_seen_rx.drain_into(&mut buffer);
            let total_updates = buffer.iter().sum::<usize>();
            buffer.clear();

            files_seen += total_updates;
            // pb.inc_many(total_updates);

            while let Ok(Some((entry, scan_result))) = files_rx.try_recv() {
                if let ScanResult::Cert(cert) = scan_result {
                    // pb.log(format!("{:?}: {:?}", cert.serial, entry.path()));
                    index.add(cert, entry.path().into());
                }
            }

            if files_rx.is_terminated() {
                break;
            }
        }

        // println!();
        // println!("{} certs found in {} files", index.len(), files_seen);
        // println!();

        // println!("Certs by type:");
        // println!("  Leaf: {}", index.len_leaf_certs());
        // println!("  Intermediate: {}", index.len_intermediate_certs());
        // println!("  Root: {}", index.len_root_certs());

        // if let Some(cert) = index.next_expiring(Timestamp::now()) {
        //     println!();
        //     println!("Next expiring certificate:");
        //     println!("  serial: {:?}", cert.cert.serial);
        //     println!("  sans: {:?}", cert.cert.sans);
        //     println!("  not after: {:?}", cert.cert.expiry.not_after);
        //     println!("  fingerprint: {:?}", cert.cert.fingerprints.sha256);

        //     println!(
        //         "  path: {}:{}:{}",
        //         cert.path.display(),
        //         cert.cert.line(),
        //         cert.cert.col()
        //     );
        // }

        if let Some(expires_in) = expires_in {
            index.emit_expiring_certs(expires_in)?;
        } else {
            let json = index.serialize();
            println!("{json:#}");
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

#[derive(Default, Debug, Serialize)]
pub struct CertIndex {
    certs: HashMap<Hex, CertWithPaths>,
}

impl CertIndex {
    pub fn add(&mut self, cert: Spanned<Cert>, path: PathBuf) {
        let fingerprint = cert.fingerprints.sha256.clone();
        let spanned_path =
            SpannedPath::new(Spanned::new(path, cert.span(), cert.line(), cert.col()));

        self.certs
            .entry(fingerprint)
            .or_insert(CertWithPaths::new(cert.into_inner(), Vec::new()))
            .add_path(spanned_path);
    }

    pub fn serialize(&self) -> serde_json::Value {
        #[derive(Serialize)]
        struct Index {
            certs: Vec<CertWithPaths>,
        }

        serde_json::to_value(&Index {
            certs: self.certs.values().map(|cert| cert.to_owned()).collect(),
        })
        .unwrap()
    }

    pub fn emit_expiring_certs(&self, expires_in: jiff::Span) -> anyhow::Result<()> {
        let now = jiff::Timestamp::now();

        for cert_with_paths in self.certs.values() {
            let cert = cert_with_paths.cert();

            let Ok(cert_expires_in) = now.until(cert.expiry.not_after) else {
                // todo: log
                continue;
            };

            // tracing::info!(%cert_expires_in, %now, expires_in=%cert.expiry.not_after, "we are here");

            match cert_expires_in.compare((&expires_in, &Zoned::now())) {
                // the cert expires _after_ expires_in, we're ok.
                Ok(Ordering::Greater) => {
                    // tracing::info!("expires in is greater!");
                }
                Ok(Ordering::Equal | Ordering::Less) => {
                    // only emit a warning if the cert is going to expire
                    if cert_expires_in.is_positive() {
                        let cert_expires_in_secs = cert_expires_in
                            .total(Unit::Second)
                            .context("unable to round Span to seconds")?
                            .floor() as i64;
                        let cert_expires_in_human = cert_expires_in
                            .round(
                                SpanRound::new()
                                    .largest(Unit::Day)
                                    .smallest(Unit::Second)
                                    .days_are_24_hours(),
                            )
                            // todo: need to not hard die here:
                            .context("unable to round certificate span")?;
                        let expires_at = cert.expiry.not_after.to_string();

                        for spanned_path in cert_with_paths.paths() {
                            let cert_path = spanned_path.path().display();
                            let cert_path_line = spanned_path.line();
                            let cert_path_col = spanned_path.col();

                            let path = format!("{cert_path}:{cert_path_line}:{cert_path_col}");

                            tracing::warn!(
                                expires_in = format!("{cert_expires_in_human:#}"),
                                expires_in_s = cert_expires_in_secs,
                                expires_at,
                                %path,
                                "certificate expiring soon"
                            );
                        }
                    } else {
                        let cert_expires_in_secs = cert_expires_in
                            .total(Unit::Second)
                            .context("unable to round Span to seconds")?
                            .floor() as i64;
                        let cert_expires_in_human = cert_expires_in
                            .round(SpanRound::new().largest(Unit::Day).days_are_24_hours())
                            // todo: need to not hard die here:
                            .context("unable to round certificate span")?;
                        let expires_at = cert.expiry.not_after.to_string();

                        for spanned_path in cert_with_paths.paths() {
                            let cert_path = spanned_path.path().display();
                            let cert_path_line = spanned_path.line();
                            let cert_path_col = spanned_path.col();

                            let path = format!("{cert_path}:{cert_path_line}:{cert_path_col}");

                            tracing::error!(
                                expires_in = format!("{cert_expires_in_human:#}"),
                                expires_in_secs = cert_expires_in_secs,
                                expires_at,
                                %path,
                                "certificate has expired"
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::error!("timestamp error! {error}");
                }
            }
        }

        Ok(())
    }
}
