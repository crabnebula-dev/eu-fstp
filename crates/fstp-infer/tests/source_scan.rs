//! TH-01: only `fstp_infer::encode` builds a chat request body (M7 design
//! section 3.3). A module elsewhere that names both the `messages` and
//! `system` members of the wire format fails this scan.

use std::fs;
use std::path::{Path, PathBuf};

/// Files that may name the request members: the encoder, and the
/// synthetic model, which reads requests.
const ALLOWED: [&str; 2] = [
    "crates/fstp-infer/src/encode.rs",
    "crates/fstp-infer/src/synthetic.rs",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if p.is_dir() {
            if name != "target" && name != "node_modules" && name != "fuzz" && name != "tests" {
                rust_files(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

/// TH-01: no module outside the encoder builds a request body.
#[test]
fn th01_only_the_encoder_builds_request_bodies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("tools"), &mut files);
    assert!(files.len() > 50, "the scan sees the workspace");
    let mut offenders = Vec::new();
    for f in files {
        let text = fs::read_to_string(&f).unwrap_or_default();
        if text.contains("\"messages\"") && text.contains("\"system\"") {
            let rel = f
                .strip_prefix(&root)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            if !ALLOWED.contains(&rel.as_str()) {
                offenders.push(rel);
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "request bodies built outside the encoder: {offenders:?}"
    );
}
