use std::ops::{Deref, Range};

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
pub mod pem;
pub mod sans;
pub mod signature;
pub mod subject;
pub mod util;

pub use jiff::Timestamp;

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
}

impl<T> Deref for Spanned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}
