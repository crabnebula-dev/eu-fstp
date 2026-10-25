//! Fuzz target for command sequences through the engine (H-05).
//!
//! This is not a parser target. It guards the workspace no-panic lints over
//! the core: input bytes become commands and oracle answers, and `decide`,
//! `apply` and `replay` must never panic. Replay must equal the incremental
//! state, and every appended record must decode.
//!
//! W0 stub: commands, the engine functions and the reference driver do not
//! exist yet. The target drives the closest existing stub, the in-memory
//! record store, with batches cut from the input. It checks that the head
//! never moves backwards and that a refused append leaves the head alone.
//! The body is replaced when the reference driver lands. The harness lane
//! (W2) owns `crates/fstp-engine/fuzz/**` after W0.

#![no_main]

use fstp_engine as _;
use fstp_ledger::{MemStore, RecordStore, Seq};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut store: MemStore<u8> = MemStore::new();
    for (i, chunk) in data.chunks(17).enumerate() {
        let Some((&first, batch)) = chunk.split_first() else {
            continue;
        };
        let head = store.head();
        let expected = if first & 1 == 0 {
            head
        } else {
            Seq::from_raw(u64::from(first))
        };
        let mut command = [0u8; 16];
        command[..8].copy_from_slice(&(i as u64).to_le_bytes());
        match store.append(expected, i64::from(first), command, batch.to_vec()) {
            Ok(seq) => assert!(seq >= head, "the head moved backwards"),
            Err(_) => assert_eq!(store.head(), head, "a refused append moved the head"),
        }
        let mut out = Vec::new();
        let _ = store.read(Seq::ZERO, 8, &mut out);
    }
});
