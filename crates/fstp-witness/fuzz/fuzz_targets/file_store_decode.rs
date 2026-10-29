//! Fuzz target `file_store_decode` of `fstp-witness` (TH-26, H-05, I-24,
//! M3 design section 15).
//!
//! Checks, for the append-only layout of `fstp_witness::encode_file_store`:
//!
//! - no panic, and decoding is deterministic.
//! - accepted records have strictly rising witness sequences from 1.
//! - an accepted file re-encodes byte for byte (round trip).
//! - the file without its last byte never decodes to the same records,
//!   so a truncation is detected or loses a whole record.
//! - the file with one more byte never decodes to the same records.
//! - `load_file_store` accepts exactly the decoded files whose sequences
//!   are 1, 2, 3 with no gap, and answers the same records.

#![no_main]

use fstp_witness::{decode_file_store, encode_file_store, load_file_store};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_file_store(data);
    assert_eq!(
        first,
        decode_file_store(data),
        "decode is not deterministic"
    );
    let loaded = load_file_store(data);
    match (&first, &loaded) {
        (Ok(rs), Ok(ls)) => assert_eq!(rs, ls, "the loader changed the records"),
        (Ok(rs), Err(_)) => assert!(
            rs.iter().zip(1u64..).any(|(r, want)| r.witness_seq != want),
            "the loader refused a store with no gap"
        ),
        (Err(_), Ok(_)) => panic!("the loader accepted a file the decoder refused"),
        (Err(_), Err(_)) => {}
    }
    if let Ok(ls) = &loaded {
        for (r, want) in ls.iter().zip(1u64..) {
            assert_eq!(r.witness_seq, want, "a gap was loaded");
        }
    }
    let Ok(records) = &first else {
        return;
    };
    if let Some(r) = records.first() {
        assert!(r.witness_seq >= 1, "witness sequence 0 accepted");
    }
    for pair in records.windows(2) {
        assert!(
            pair[0].witness_seq < pair[1].witness_seq,
            "witness sequence does not rise"
        );
    }
    assert_eq!(
        encode_file_store(records).as_deref().ok(),
        Some(data),
        "an accepted file does not re-encode to its input"
    );
    if let Some((_, head)) = data.split_last() {
        assert_ne!(
            decode_file_store(head).as_ref().ok(),
            Some(records),
            "truncation undetected"
        );
    }
    let mut longer = data.to_vec();
    longer.push(0);
    assert_ne!(
        decode_file_store(&longer).as_ref().ok(),
        Some(records),
        "trailing byte accepted"
    );
});
