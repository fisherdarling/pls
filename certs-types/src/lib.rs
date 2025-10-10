pub mod cert;
pub mod crl;
pub mod csr;
pub mod expiry;
pub mod extensions;
pub mod id;
pub mod issuer;
pub mod key;
pub mod nid;
pub mod ocsp;
pub mod output;
pub mod pem;
pub mod sans;
pub mod signature;
pub mod subject;
pub mod util;

use std::{
    ops::{Deref, Range},
    path::{Path, PathBuf},
};

pub use jiff::Timestamp;
use serde_with::SerializeDisplay;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    span: Range<usize>,
    line: usize,
    col: usize,
    data: T,
}

impl<T> Spanned<T> {
    pub fn new(data: T, span: Range<usize>, line: usize, col: usize) -> Self {
        Self {
            data,
            span,
            line,
            col,
        }
    }

    pub fn span(&self) -> Range<usize> {
        self.span.clone()
    }

    pub fn line(&self) -> usize {
        self.line
    }

    pub fn col(&self) -> usize {
        self.col
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T> Deref for Spanned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[derive(Debug, Clone, PartialEq, Eq, SerializeDisplay)]
pub struct SpannedPath {
    inner: Spanned<PathBuf>,
}

impl SpannedPath {
    pub fn new(inner: Spanned<PathBuf>) -> Self {
        Self { inner }
    }

    pub fn path(&self) -> &Path {
        &self.inner
    }

    pub fn line(&self) -> usize {
        self.inner.line()
    }

    pub fn col(&self) -> usize {
        self.inner.col()
    }
}

impl std::fmt::Display for SpannedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.inner.data().display(),
            self.inner.line(),
            self.inner.col()
        )
    }
}
