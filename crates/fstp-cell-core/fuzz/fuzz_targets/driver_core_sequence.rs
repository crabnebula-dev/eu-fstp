//! Fuzz target `driver_core_sequence` of `fstp-cell-core` (TH-26, H-05, M3
//! design section 15).
//!
//! Design checks: random needs and events never panic. One admitted
//! command runs through `DriverCore`, and the input picks every event, of
//! any kind and in any order, including events that fit no need. Answers
//! are built from the queries of the need they answer, so the vault
//! reaction is decided, appended and acknowledged too (NOTE 4).
//!
//! The command is the erasure runner's `RecordEpochDestroyed`, admitted
//! by `gate::admit_system` ([`driver_events`]). That admission needs no
//! session, so the target drives the driver without `fstp-auth` (lane
//! W2b). When `replay(&[])` or the gate refuses, the target checks only
//! that the refusal formats.

#![no_main]

#[path = "driver_events.rs"]
mod driver_events;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let outcome = driver_events::run(data);
    assert!(outcome.reaction_acks <= driver_events::MAX_STEPS);
    if let Some(r) = outcome.done {
        assert!(!format!("{r:?}").is_empty());
    }
});
