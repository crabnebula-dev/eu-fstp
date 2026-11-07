//! Licence detection on a deliverable's licence file (R-PR-02, P-26).
//!
//! The file is untrusted data. Detection reads only the
//! `SPDX-License-Identifier:` tags of its first [`MAX_SCAN`] bytes and
//! keeps nothing of the file but the parsed expression. Matching full
//! licence texts needs a vetted copy of the SPDX licence list texts, which
//! the repository does not hold yet, so a file without a tag is reported
//! as such. `TODO(legal)`: whether an untagged licence text may count.

use crate::spdx::{Expr, parse};

/// The most bytes of a licence file that detection reads.
pub const MAX_SCAN: usize = 256 * 1024;
/// The most tags detection reads.
const MAX_TAGS: usize = 64;
/// The tag that names the licence.
const TAG: &str = "SPDX-License-Identifier:";

/// What detection found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detected {
    /// One expression, possibly tagged several times.
    Found(Expr),
    /// No tag.
    Absent,
    /// A tag whose value is not a valid expression.
    Invalid,
    /// Tags that name different expressions.
    Conflict,
}

/// Detects the licence expression of the licence file `bytes`.
pub fn detect(bytes: &[u8]) -> Detected {
    let head = bytes.get(..MAX_SCAN).unwrap_or(bytes);
    let mut found: Option<Expr> = None;
    let mut seen = 0usize;
    for line in head.split(|b| *b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let Some((_, value)) = line.split_once(TAG) else {
            continue;
        };
        seen = seen.saturating_add(1);
        if seen > MAX_TAGS {
            break;
        }
        let value = value
            .trim()
            .trim_end_matches("*/")
            .trim_end_matches("-->")
            .trim();
        let Ok(e) = parse(value) else {
            return Detected::Invalid;
        };
        match &found {
            Some(f) if !f.same(&e) => return Detected::Conflict,
            Some(_) => {}
            None => found = Some(e),
        }
    }
    found.map_or(Detected::Absent, Detected::Found)
}
