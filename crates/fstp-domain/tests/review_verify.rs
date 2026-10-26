//! Adversarial verification reproducers for the W1c interface fixes.
//!
//! Each test fails against the code under review and passes once the
//! named defect is fixed. Production code is not changed here.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `src/`, as (path relative to `src/`, text), in sorted order.
fn sources() -> Result<Vec<(String, String)>, String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot list {}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, base, out)?;
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)
                    .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
                let rel = p
                    .strip_prefix(base)
                    .map(|r| r.display().to_string())
                    .unwrap_or_default();
                out.push((rel, text));
            }
        }
        Ok(())
    }
    let base = src_dir();
    let mut out = Vec::new();
    walk(&base, &base, &mut out)?;
    Ok(out)
}

/// Design section 10: no two agents own the same file. Fixes 13 and 18
/// declared cross-lane seams (`from_decoded`, `active_binding`,
/// `latest_published_seq`) in one lane's file for another lane to call, and
/// marked each `#[expect(dead_code)]`. The first call from the consuming
/// lane leaves that expectation unfulfilled, which `-D warnings` turns into
/// an error in the owner's file. So L-SOD must edit `programme.rs` while
/// L-POL owns it in parallel W3, L-POL must edit `roles/mod.rs` likewise,
/// and L-CODEC must edit `decision.rs`, `grant.rs` and `payment.rs`.
#[test]
fn review_cross_lane_seams_need_no_edit_by_the_consuming_lane() {
    let files = match sources() {
        Ok(f) => f,
        Err(e) => panic!("{e}"),
    };
    let mut hits = Vec::new();
    for (rel, text) in &files {
        for (n, line) in text.lines().enumerate() {
            if line.contains("#[expect(dead_code") && line.contains("lane") {
                hits.push(format!("src/{rel}:{}", n.saturating_add(1)));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "cross-lane seams marked #[expect(dead_code)] force the calling lane to edit the owner's file: {hits:?}"
    );
}
