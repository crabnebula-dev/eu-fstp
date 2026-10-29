//! Fuzz target `cell_decide_sequence` of `fstp-cell-core` (TH-26, H-05, M3
//! design section 15).
//!
//! Design checks: `queries`, `decide`, `apply` and `replay` never panic;
//! every decided record reads back from its stored bytes; every decided
//! batch folds; replay of the whole ledger equals the state
//! folded entry by entry (I-23).
//!
//! The input is a sequence of length-prefixed frames, each a control
//! byte, an actor and one canonical command ([`decide_frames`]). The
//! commands are decided under a command id, so the SoD-07 path runs too.
//! The seeds hold the M2 setup commands of the corpus, so the M2
//! programme, call and grant paths are decided.

#![no_main]

#[path = "decide_frames.rs"]
mod decide_frames;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decide_frames::run(data);
});
