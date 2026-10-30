//! The shipped profile tree (M4 design sections 1.3 rule A9b and 3.10).
//!
//! - The shipped Horizon Europe Guide template equals the specification's
//!   template byte for byte.
//! - No file under `crates/fstp-guide/profiles/` holds the synthetic
//!   legal-wording marker. The marker is assembled at run time, so this
//!   file never holds it either.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use fstp_guide::{HORIZON_EUROPE, ProfileSource, ShippedProfiles};

/// The specification's Guide template.
const SPEC_GUIDE: &[u8] =
    include_bytes!("../../../SPEC/profiles/horizon-europe/guide-for-applicants.md");

/// The synthetic legal-wording marker of rule A9b.
fn marker() -> String {
    ["SYNTHETIC", "TEST", "WORDING"].join(" ")
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// R-GA-01, I-51: the shipped template is the specification's template,
/// byte for byte, and the shipped source serves it.
#[test]
fn r_ga_01_shipped_guide_equals_the_spec_template() {
    let shipped = ShippedProfiles.files(HORIZON_EUROPE).unwrap();
    assert_eq!(shipped.guide, SPEC_GUIDE);
    let profile = ShippedProfiles.profile(HORIZON_EUROPE).unwrap();
    assert_eq!(profile.guide_template().as_bytes(), SPEC_GUIDE);
}

/// A9b: no shipped profile file holds the synthetic marker, and the tree
/// holds the Horizon Europe template.
#[test]
fn a9b_shipped_profile_tree_holds_no_synthetic_marker() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
    let mut files = Vec::new();
    files_under(&root, &mut files);
    assert!(
        files
            .iter()
            .any(|f| f.ends_with("horizon-europe/guide.v1.md")),
        "the Horizon Europe template is shipped: {files:?}"
    );
    let marker = marker();
    for f in &files {
        let bytes = fs::read(f).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&marker),
            "{} holds the synthetic marker",
            f.display()
        );
    }
}
