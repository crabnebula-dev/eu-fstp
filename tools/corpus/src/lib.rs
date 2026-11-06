//! The synthetic corpus generator `template-v1` (M7 design section 5,
//! `SPEC/07-test-plan/synthetic-corpus.md`). It is a build tool and never
//! ships.
//!
//! No model writes the corpus. Every text comes from the templates and
//! the topic table in [`text`], filled in deterministically from a seed.
//! The output lives under `corpus/v1/`:
//!
//! - `manifest.json`: the labels. One entry per item with its variant, its
//!   base, its canaries, its rubric elements, its expected findings and
//!   the fixture URLs it relies on.
//! - `items/<id>.json`: one proposal with its applicant facts.
//! - `web/<host>/<path>`: the fixture pages that `fstp-fixture-web` serves
//!   to retrieval inside tests. Every host ends in `.test`.
//!
//! Synthetic data only. Person, street, town, project and handle names are
//! built from [`SYLLABLES`]. Emails use `example.org`. Phones sit in the
//! fictional range of [`PHONE_PREFIX`]. IBAN-shaped canaries use the bank
//! code [`IBAN_BANK_CODE`], which the generator writes nowhere else. Every
//! file is ASCII: non-ASCII characters of the hidden injections are
//! written as JSON escapes.

mod build;
mod text;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

pub use build::generate;

/// The generator name every evaluation report states.
pub const GENERATOR: &str = "template-v1";

/// The seed of `corpus/v1`.
pub const V1_SEED: u64 = 20_261_106;

/// The PII classes. Every item carries one canary of each.
pub const PII_CLASSES: [&str; 5] = ["person_name", "email", "phone", "iban", "postal_address"];

/// The closed rubric element tags (M7 design section 2, reading 1).
pub const RUBRIC_ELEMENTS: [&str; 7] = [
    "problem",
    "approach",
    "ois_relevance",
    "team_experience",
    "deliverables_licence",
    "milestones",
    "budget_justification",
];

/// The invented syllables every generated name is built from.
pub const SYLLABLES: [&str; 24] = [
    "zor", "vak", "quel", "lin", "thra", "mib", "osk", "ul", "fen", "dro", "vy", "kal", "sef",
    "yn", "brax", "ilo", "tesh", "orv", "qua", "zim", "pel", "ruk", "nae", "gow",
];

/// The fictional phone range of every phone canary, followed by three
/// digits.
pub const PHONE_PREFIX: &str = "+44 20 7946 0";

/// The bank code of every IBAN-shaped canary. No other text uses it.
pub const IBAN_BANK_CODE: &str = "00000000";

/// The parts of a corpus version the generator owns. `recordings/` and
/// `panel/` belong to the evaluation harness.
const OWNED: [&str; 3] = ["manifest.json", "items", "web"];

/// A generated corpus version: relative path to file bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Corpus {
    files: BTreeMap<String, Vec<u8>>,
}

impl Corpus {
    /// Every file, by its path relative to the version directory.
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// One file by its relative path.
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// The paths under `dir` that differ from this corpus: missing,
    /// different or extra files among the generator-owned parts.
    ///
    /// # Errors
    ///
    /// An I/O error other than a missing file.
    pub fn check_against(&self, dir: &Path) -> io::Result<Vec<String>> {
        let on_disk = read_owned(dir)?;
        let mut stale = Vec::new();
        for (path, bytes) in &self.files {
            if on_disk.get(path) != Some(bytes) {
                stale.push(path.clone());
            }
        }
        for path in on_disk.keys() {
            if !self.files.contains_key(path) {
                stale.push(path.clone());
            }
        }
        Ok(stale)
    }

    /// Writes the corpus under `dir` and removes extra files among the
    /// generator-owned parts.
    ///
    /// # Errors
    ///
    /// Any I/O error.
    pub fn write_to(&self, dir: &Path) -> io::Result<()> {
        for path in read_owned(dir)?.keys() {
            if !self.files.contains_key(path) {
                std::fs::remove_file(dir.join(path))?;
            }
        }
        for (path, bytes) in &self.files {
            let target = dir.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if std::fs::read(&target).ok().as_ref() != Some(bytes) {
                std::fs::write(&target, bytes)?;
            }
        }
        Ok(())
    }
}

/// `corpus/v1` of this repository.
pub fn default_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../corpus/v1"))
}

/// The generator-owned files under `dir`, by relative path.
fn read_owned(dir: &Path) -> io::Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for part in OWNED {
        walk(dir, Path::new(part), &mut out)?;
    }
    Ok(out)
}

fn walk(root: &Path, rel: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> io::Result<()> {
    let full = root.join(rel);
    let meta = match std::fs::metadata(&full) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.is_dir() {
        for entry in std::fs::read_dir(&full)? {
            let entry = entry?;
            walk(root, &rel.join(entry.file_name()), out)?;
        }
    } else {
        let key = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        out.insert(key, std::fs::read(&full)?);
    }
    Ok(())
}

impl Corpus {
    pub(crate) fn from_files(files: BTreeMap<String, Vec<u8>>) -> Corpus {
        Corpus { files }
    }
}
