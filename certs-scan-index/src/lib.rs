use std::{collections::BTreeMap, path::PathBuf};

use certs_types::{
    Timestamp,
    Spanned,
    cert::{Cert, CertDepth},
    subject::Subject,
};

type Idx = usize;

#[derive(Debug, Clone)]
pub struct CertWithPath {
    pub path: PathBuf,
    pub cert: Spanned<Cert>,
}

#[derive(Debug, Clone)]
pub struct CertIndex {
    certs: Vec<CertWithPath>,
    certs_by_not_after: BTreeMap<Timestamp, Vec<Idx>>,
    certs_by_not_before: BTreeMap<Timestamp, Vec<Idx>>,
    certs_by_subject: BTreeMap<Subject, Vec<Idx>>,
    certs_by_path: BTreeMap<PathBuf, Vec<Idx>>,
    certs_by_depth: BTreeMap<CertDepth, Vec<Idx>>,
}

impl CertIndex {
    pub fn new() -> Self {
        Self {
            certs: Vec::new(),
            certs_by_not_after: BTreeMap::new(),
            certs_by_not_before: BTreeMap::new(),
            certs_by_subject: BTreeMap::new(),
            certs_by_path: BTreeMap::new(),
            certs_by_depth: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, cert: Spanned<Cert>, path: PathBuf) {
        let idx = self.certs.len();
        self.certs.push(CertWithPath { cert, path });

        self.certs_by_not_after
            .entry(self.certs[idx].cert.expiry.not_after)
            .or_default()
            .push(idx);

        self.certs_by_not_before
            .entry(self.certs[idx].cert.expiry.not_before)
            .or_default()
            .push(idx);

        self.certs_by_subject
            .entry(self.certs[idx].cert.subject.clone())
            .or_default()
            .push(idx);

        self.certs_by_path
            .entry(self.certs[idx].path.clone())
            .or_default()
            .push(idx);

        self.certs_by_depth
            .entry(self.certs[idx].cert.classification.depth.clone())
            .or_default()
            .push(idx);
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn len_leaf_certs(&self) -> usize {
        self.certs_by_depth
            .get(&CertDepth::Leaf)
            .map(|idxs| idxs.len())
            .unwrap_or(0)
    }

    pub fn len_intermediate_certs(&self) -> usize {
        self.certs_by_depth
            .get(&CertDepth::Intermediate)
            .map(|idxs| idxs.len())
            .unwrap_or(0)
    }

    pub fn len_root_certs(&self) -> usize {
        self.certs_by_depth
            .get(&CertDepth::Root)
            .map(|idxs| idxs.len())
            .unwrap_or(0)
    }

    pub fn next_expiring(&self, now: Timestamp) -> Option<&CertWithPath> {
        for (not_after, idxs) in self.certs_by_not_after.iter() {
            if now < *not_after {
                return Some(&self.certs[idxs[0]]);
            }
        }

        None
    }
}
