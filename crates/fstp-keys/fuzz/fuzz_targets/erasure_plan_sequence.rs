//! Fuzz target `erasure_plan_sequence` of `fstp-keys` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: random step sequences keep the M-SHRED predicates.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2f lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use fstp_keys::Epoch;
    use fstp_keys::erasure::{ChainState, Step, apply, next};
    let mut state = ChainState::genesis(Epoch(0));
    for b in data.iter().take(64) {
        let epoch = Epoch(u64::from(*b));
        let step = match b % 6 {
            0 => Step::NewEpoch(epoch),
            1 => Step::RewrapGroups(epoch),
            2 => Step::Commit(epoch),
            3 => Step::Snapshot(epoch),
            4 => Step::VerifySnapshot(epoch),
            _ => Step::DestroyRoot(epoch),
        };
        if apply(&mut state, &step).is_err() {
            break;
        }
    }
    let shown = format!("{:?}", next(&state));
    assert!(!shown.is_empty());
});
