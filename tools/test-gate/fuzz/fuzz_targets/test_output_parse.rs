//! Fuzz target for the cargo test output reader and the known-red list
//! parser of test-gate (TH-26).
//!
//! Beyond "no panic": every key belongs to a binary that ran, every
//! unfinished binary ran, accepted list entries are unique and render back
//! to the same entries, and the check's problems are sorted and unique.

#![no_main]

use libfuzzer_sys::fuzz_target;
use test_gate::{check, read_list, read_run};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let run = read_run(&text);
    for key in run.tests.keys() {
        let owned = run
            .binaries
            .iter()
            .any(|b| key.starts_with(&format!("{b}::")));
        assert!(owned, "key {key:?} names no binary that ran");
    }
    for b in &run.unfinished {
        assert!(run.binaries.contains(b), "unfinished {b:?} never ran");
    }
    if let Ok(entries) = read_list(&text) {
        let mut keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        keys.sort_unstable();
        let n = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), n, "duplicate keys accepted");
        let rendered: String = entries
            .iter()
            .map(|e| format!("{} | {} | {}\n", e.key, e.seam, e.lane))
            .collect();
        assert_eq!(
            read_list(&rendered).ok(),
            Some(entries.clone()),
            "render round trip"
        );
        let problems = check(&run, &entries);
        assert!(
            problems.windows(2).all(|w| w[0] < w[1]),
            "problems not sorted and unique"
        );
    }
});
