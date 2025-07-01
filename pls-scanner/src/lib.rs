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
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bon::Builder;
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::{DirEntry, WalkBuilder, WalkState};
use kanal::Receiver;
use memmap2::Mmap;
use pls_parser::{ParsedItem, Spanned};
use pls_settings::CertScanLevels;
use pls_types::cert::{Cert, CertDepth};

#[derive(Clone, Builder)]
pub struct ScanConfig {
    pub roots: Vec<PathBuf>,
    pub file_types: GlobSet,
    pub ignore_globs: GlobSet,
    pub gitignore: bool,
    pub scan_levels: CertScanLevels,
}

impl std::fmt::Debug for ScanConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ScanConfig {
            roots,
            file_types: _,
            ignore_globs: _,
            gitignore,
            scan_levels,
        } = self;

        f.debug_struct("ScanConfig")
            .field("roots", &roots)
            .field("gitignore", &gitignore)
            .field("scan_levels", &scan_levels)
            .finish()
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig::from(&pls_settings::Settings::default())
    }
}

pub fn scan(config: ScanConfig) -> (Receiver<(ignore::DirEntry, ScanResult)>, Receiver<usize>) {
    // let start = Instant::now();

    let mut roots = config.roots.iter();

    let mut builder = WalkBuilder::new(roots.next().unwrap());
    for root in roots {
        builder.add(root);
    }

    builder.git_exclude(config.gitignore);

    let (files_tx, parsed_rx) = start_parse_pool(config.scan_levels.clone());
    let config = Arc::new(config);

    let (files_seen_tx, files_seen_rx) = kanal::bounded(1000);
    std::thread::spawn(move || {
        let config = Arc::clone(&config);

        builder.build_parallel().run(move || {
            let update_every = Duration::from_micros(100 + fastrand::u64(0..100));

            let files_seen_tx = files_seen_tx.clone();
            let files_tx = files_tx.clone();

            let mut state =
                ThreadState::new(Arc::clone(&config), update_every, files_seen_tx, files_tx);

            Box::new({
                let config = Arc::clone(&config);
                move |entry| {
                    let Ok(entry) = entry else {
                        return WalkState::Continue;
                    };

                    let Some(file_type) = entry.file_type() else {
                        return WalkState::Continue;
                    };

                    if file_type.is_dir() && config.ignore_globs.is_match(entry.path()) {
                        // println!("skipping dir: {}", entry.path().display());
                        return WalkState::Skip;
                    }

                    if file_type.is_file() {
                        state.mark(entry);
                    }

                    WalkState::Continue
                }
            })
        });
    });

    (parsed_rx, files_seen_rx)
}

pub struct ThreadState {
    pub config: Arc<ScanConfig>,
    pub count: usize,
    pub last_update: Instant,
    pub update_every: Duration,
    pub files_seen_tx: kanal::Sender<usize>,
    pub files_tx: kanal::Sender<Vec<DirEntry>>,
    pub batch: Vec<DirEntry>,
}

impl ThreadState {
    pub fn new(
        config: Arc<ScanConfig>,
        update_every: Duration,
        files_seen_tx: kanal::Sender<usize>,
        files_tx: kanal::Sender<Vec<DirEntry>>,
    ) -> Self {
        Self {
            config,
            count: 0,
            last_update: Instant::now(),
            update_every,
            files_seen_tx,
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
            self.files_tx.send(std::mem::take(&mut self.batch)).unwrap();
            self.files_seen_tx.send(self.count).unwrap();
            self.count = 0;
        }

        self.last_update = Instant::now();
    }
}

impl Drop for ThreadState {
    fn drop(&mut self) {
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

#[derive(Debug)]
pub enum ScanResult {
    Cert(Spanned<Cert>),
    Other,
    Error(Spanned<String>, anyhow::Error),
}

pub fn start_parse_pool(
    scan_levels: CertScanLevels,
) -> (
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

                                    match span.classification.depth {
                                        CertDepth::Leaf => {
                                            if !scan_levels.leaf {
                                                continue;
                                            }
                                        }
                                        CertDepth::Intermediate => {
                                            if !scan_levels.intermediate {
                                                continue;
                                            }
                                        }
                                        CertDepth::Root => {
                                            if !scan_levels.root {
                                                continue;
                                            }
                                        }
                                    }

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

impl From<&pls_settings::Settings> for ScanConfig {
    fn from(settings: &pls_settings::Settings) -> Self {
        Self {
            roots: settings.scanning.roots.clone(),
            file_types: build_globset(&settings.scanning.file_types),
            ignore_globs: build_globset(&settings.scanning.ignore_paths),
            gitignore: settings.scanning.respect_gitignore,
            scan_levels: settings.scanning.levels.clone(),
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
