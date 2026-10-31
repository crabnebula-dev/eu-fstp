//! Fuzz target `proc_maps_decode` of `fstp-celltest` (TH-26, H-05, M3
//! design section 15).
//!
//! Design check: no panic. The decoder is a test-only parser, but the I-80
//! memory scan reads `/proc/<pid>/mem` only through the regions it returns,
//! so an accepted input must also describe sane regions:
//!
//! - every region is non-empty (`start < end`);
//! - a text of `n` lines yields at most `n` regions;
//! - a path is non-empty, holds no newline and starts with no space;
//! - decoding is deterministic;
//! - a readable region comes from a line whose perms start with `r`, so
//!   the count of readable regions never exceeds the count of such lines.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_celltest::procmem::decode_proc_maps(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    let Ok(regions) = first else {
        return;
    };
    assert_eq!(
        fstp_celltest::procmem::decode_proc_maps(data).ok(),
        Some(regions.clone()),
        "decoding is not deterministic"
    );
    let lines: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();
    assert!(regions.len() <= lines.len(), "more regions than lines");
    let readable_lines = lines
        .iter()
        .filter(|l| {
            l.split(|b| *b == b' ')
                .nth(1)
                .is_some_and(|p| p.first() == Some(&b'r'))
        })
        .count();
    let readable = regions.iter().filter(|r| r.readable).count();
    assert!(
        readable <= readable_lines,
        "a readable region without an r perm"
    );
    for r in &regions {
        assert!(r.start < r.end, "empty or inverted region {r:?}");
        if let Some(p) = &r.path {
            assert!(!p.is_empty(), "empty path in {r:?}");
            assert!(!p.contains('\n'), "newline in path {r:?}");
            assert!(!p.starts_with(' '), "padding kept in path {r:?}");
        }
    }
});
