//! Fuzz target `witness_message_decode` of `fstp-witness` (TH-26, H-05,
//! I-24, M3 design section 15).
//!
//! Checks, for the one layout of `fstp_witness::encode_witness_message`
//! over a prepare, an abort or an in-doubt record:
//!
//! - no panic, and decoding is deterministic.
//! - an accepted message re-encodes byte for byte (round trip).
//! - neither the input without its last byte nor the input with one more
//!   byte decodes to the same message.
//! - an abort or an in-doubt record for an unknown prepare is refused by
//!   a fresh witness core, even from the chain's own writer.

#![no_main]

use fstp_witness::{
    ChainWitness, Refusal, Sender, WitnessMessage, decode_witness_message, encode_witness_message,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_witness_message(data);
    assert_eq!(
        first,
        decode_witness_message(data),
        "decode is not deterministic"
    );
    let Ok(m) = &first else {
        return;
    };
    assert_eq!(
        encode_witness_message(m).as_deref().ok(),
        Some(data),
        "an accepted message does not re-encode to its input"
    );
    if let Some((_, head)) = data.split_last() {
        assert_ne!(
            decode_witness_message(head).as_ref().ok(),
            Some(m),
            "truncation accepted"
        );
    }
    let mut longer = data.to_vec();
    longer.push(0);
    assert_ne!(
        decode_witness_message(&longer).as_ref().ok(),
        Some(m),
        "trailing byte accepted"
    );
    match m {
        WitnessMessage::Abort {
            cell,
            chain,
            n,
            link,
        } => {
            let mut w = ChainWitness::genesis(*cell, *chain);
            let got = w.abort(Sender::writer(*cell, *chain), *n, link);
            assert_eq!(
                got,
                Err(Refusal::UnknownPrepare),
                "abort of an unknown prepare"
            );
        }
        WitnessMessage::InDoubtAbsent {
            cell,
            chain,
            n,
            link,
        } => {
            let mut w = ChainWitness::genesis(*cell, *chain);
            let got = w.in_doubt_absent(Sender::writer(*cell, *chain), *n, link);
            assert_eq!(
                got,
                Err(Refusal::UnknownPrepare),
                "in doubt of an unknown prepare"
            );
        }
        WitnessMessage::Prepare(_) => {}
    }
});
