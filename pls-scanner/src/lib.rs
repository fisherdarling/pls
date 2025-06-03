// let path: PathBuf = std::env::args()
//     .nth(1)
//     .unwrap_or_else(|| ".".to_string())
//     .into();
// let path = path.canonicalize().unwrap();

// let mut types_builder = TypesBuilder::new();
// types_builder.add_def("rust:*.rs").unwrap();
// types_builder.add_def("pem:*.pem").unwrap();
// types_builder.select("rust");
// types_builder.select("pem");

// let walker = WalkBuilder::new(path)
//     .types(types_builder.build().unwrap())
//     .build_parallel();

// walker.run(|| {
//     Box::new(|entry| {
//         let Ok(entry) = entry else {
//             return WalkState::Continue;
//         };

//         let Some(map) = map_file(&entry.path()) else {
//             return WalkState::Continue;
//         };

//         println!("{}: {}", entry.path().display(), hash_file(&map));

//         WalkState::Continue
//     })
// });

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    iter::Scan,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bon::Builder;
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::{DirEntry, WalkBuilder, WalkState};
use indicatif::ProgressStyle;
use memmap2::Mmap;
use pls_parser::{ParsedItem, Spanned};
use pls_settings::ScanSettings;
use pls_types::cert::Cert;

#[derive(Clone, Builder)]
pub struct ScanConfig {
    pub roots: Vec<PathBuf>,
    pub file_types: GlobSet,
    pub ignore_globs: GlobSet,
}

impl std::fmt::Debug for ScanConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ScanConfig {
            roots,
            file_types: _,
            ignore_globs: _,
        } = self;

        f.debug_struct("ScanConfig").field("roots", &roots).finish()
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanSettings::default().into()
    }
}

pub fn scan(config: ScanConfig) -> () {
    let mut roots = config.roots.iter();

    let mut builder = WalkBuilder::new(roots.next().unwrap());
    for root in roots {
        builder.add(root);
    }

    let (files_tx, parsed_rx) = start_parse_pool();
    let config = Arc::new(config);

    let (tx, rx) = kanal::bounded(1000);
    std::thread::spawn(move || {
        let config = Arc::clone(&config);

        builder.build_parallel().run(move || {
            let update_every = Duration::from_micros(100 + fastrand::u64(0..100));
            let update_tx = tx.clone();
            let files_tx = files_tx.clone();

            let mut state =
                ThreadState::new(Arc::clone(&config), update_every, update_tx, files_tx);

            Box::new(move |entry| {
                let Ok(entry) = entry else {
                    return WalkState::Continue;
                };

                let Some(file_type) = entry.file_type() else {
                    return WalkState::Continue;
                };

                if file_type.is_file() {
                    state.mark(entry);
                }

                WalkState::Continue
            })
        });
    });

    let mut parsed = 0;
    let progress = indicatif::ProgressBar::new_spinner().with_style(
        ProgressStyle::with_template("{spinner} {msg} {human_len:7} files {elapsed_precise}")
            .unwrap(),
    );
    progress.enable_steady_tick(Duration::from_millis(50));
    progress.set_message(format!("found {:4} certs", parsed));

    loop {
        match parsed_rx.try_recv() {
            Ok(Some((entry, pem))) => {
                match pem {
                    ScanResult::Cert(pem) => {
                        let is_ca =
                            pem.public_key.usage.key_cert_sign || pem.public_key.usage.crl_sign;

                        if !is_ca {
                            progress.println(format!(
                                "[{:5}] parsed leaf cert in {}:{}:{}",
                                parsed,
                                entry.path().display(),
                                pem.line(),
                                pem.col(),
                            ));
                            parsed += 1;
                        }

                        progress.set_message(format!("found {parsed} certs in"));
                    }
                    ScanResult::Error(span, error) => {
                        // progress.println(format!(
                        //     "[{:5}] failed to parse {:?} in {}:{}:{:?} {error}",
                        //     parsed,
                        //     &*span,
                        //     entry.path().display(),
                        //     span.line(),
                        //     span.col(),
                        // ));
                    }
                    ScanResult::Other => {
                        // continue;
                    }
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }

        if let Ok(count) = rx.recv_timeout(Duration::from_millis(10)) {
            progress.inc(count as u64);
        }
    }

    progress.set_message(format!("found {:4} certs", parsed));
    progress.finish_using_style();
    println!("found {:4} certs", parsed);
}

pub struct GlobalScanState {}

pub struct ThreadState {
    pub config: Arc<ScanConfig>,
    pub count: usize,
    pub last_update: Instant,
    pub update_every: Duration,
    pub tx: kanal::Sender<usize>,
    pub files_tx: kanal::Sender<Vec<DirEntry>>,
    pub batch: Vec<DirEntry>,
}

impl ThreadState {
    pub fn new(
        config: Arc<ScanConfig>,
        update_every: Duration,
        tx: kanal::Sender<usize>,
        files_tx: kanal::Sender<Vec<DirEntry>>,
    ) -> Self {
        Self {
            config,
            count: 0,
            last_update: Instant::now(),
            update_every,
            tx,
            files_tx,
            batch: Vec::new(),
        }
    }

    pub fn mark(&mut self, entry: DirEntry) {
        self.count += 1;

        if self.config.file_types.is_match(entry.path())
            && !self.config.ignore_globs.is_match(entry.path())
        {
            self.batch.push(entry);
        }

        if self.last_update.elapsed() > self.update_every {
            self.tx.send(self.count).unwrap();
            self.count = 0;
            self.files_tx.send(std::mem::take(&mut self.batch)).unwrap();
        }

        self.last_update = Instant::now();
    }
}

impl Drop for ThreadState {
    fn drop(&mut self) {
        self.tx.send(self.count).unwrap();
        self.files_tx.send(std::mem::take(&mut self.batch)).unwrap();
    }
}

fn map_file(path: &Path) -> Option<Mmap> {
    let file = File::open(path).ok()?;
    let map = unsafe {
        memmap2::MmapOptions::new()
            .map(&file)
            .inspect_err(|err| {
                println!("failed to map file at {:?}: {err}", path);
            })
            .ok()?
    };
    Some(map)
}

// fn hash_file(bytes: &[u8]) -> String {
//     let hasher = gxhash::gxhash64(bytes, 0);
//     format!("{:016x}", hasher)
// }

pub enum ScanResult {
    Cert(Spanned<Cert>),
    Other,
    Error(Spanned<String>, anyhow::Error),
}

pub fn start_parse_pool() -> (
    kanal::Sender<Vec<DirEntry>>,
    kanal::Receiver<(DirEntry, ScanResult)>,
) {
    let pool = rayon::ThreadPoolBuilder::new().build().unwrap();

    let (files_tx, files_rx) = kanal::unbounded::<Vec<DirEntry>>();
    let (parsed_tx, parsed_rx) = kanal::unbounded();

    std::thread::spawn(move || {
        while let Ok(entries) = files_rx.recv() {
            for entry in entries {
                let parsed_tx = parsed_tx.clone();

                pool.spawn(move || {
                    let path = entry.path();

                    let Some(map) = map_file(&path) else {
                        return;
                    };

                    let parser = pls_parser::Parser::new(&map);

                    for pem in parser.parse() {
                        match pem {
                            ParsedItem::SpannedParsedPem(pem) => {
                                let (span, line, col) = (pem.span(), pem.line(), pem.col());
                                if let Some(cert) = pem.into_cert() {
                                    let span = Spanned::new(cert, span, line, col);
                                    parsed_tx
                                        .send((entry.clone(), ScanResult::Cert(span)))
                                        .unwrap();
                                } else {
                                    parsed_tx.send((entry.clone(), ScanResult::Other)).unwrap();
                                }
                            }
                            ParsedItem::DecodeFailedPem(raw_pem, error) => {
                                let span = Spanned::new(
                                    String::from_utf8_lossy(raw_pem.label()).to_string(),
                                    raw_pem.span(),
                                    raw_pem.line(),
                                    raw_pem.col(),
                                );

                                parsed_tx
                                    .send((entry.clone(), ScanResult::Error(span, error)))
                                    .unwrap();
                            }
                        }
                    }
                });
            }
        }
    });

    (files_tx, parsed_rx)
}

fn default_globset() -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    let filetypes = [
        "pem",
        "crt",
        "csr",
        "key",
        "json",
        "ca-bundle",
        "p7b",
        "p7s",
        "pfx",
        "p12",
    ];

    for filetype in filetypes {
        builder.add(
            GlobBuilder::new(format!("*.{}", filetype).as_str())
                .case_insensitive(true)
                .build()
                .unwrap(),
        );
    }

    builder.build().unwrap()
}

pub struct ScanState {
    top_level: BTreeSet<PathBuf>,
    certs: BTreeMap<PathBuf, Vec<Cert>>,
    total: usize,
    success: usize,
    failed: usize,
}

impl From<pls_settings::ScanSettings> for ScanConfig {
    fn from(settings: pls_settings::ScanSettings) -> Self {
        Self {
            roots: settings.roots,
            file_types: build_globset(&settings.file_types),
            ignore_globs: build_globset(&settings.ignore_paths),
        }
    }
}

fn build_globset(globs: &[String]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for glob in globs {
        builder.add(Glob::new(glob).unwrap());
    }
    builder.build().unwrap()
}
