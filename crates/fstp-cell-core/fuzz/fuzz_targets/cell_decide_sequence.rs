//! Fuzz target `cell_decide_sequence` of `fstp-cell-core` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: decide, apply and replay never panic; replay equals incremental state.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2c lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use fstp_cell_core::{CellCtx, decode_cell_command, queries, replay};
    let commands: Vec<_> = data
        .chunks(64)
        .filter_map(|c| decode_cell_command(c).ok())
        .collect();
    match replay(&[]) {
        Ok(state) => {
            let ctx = CellCtx {
                actor: fstp_domain::id::AccountId::from_raw(1),
                at: 0,
            };
            for c in &commands {
                let shown = format!("{:?}", queries(&state, c, &ctx));
                assert!(!shown.is_empty());
            }
        }
        Err(e) => assert!(!format!("{e:?}").is_empty()),
    }
});
