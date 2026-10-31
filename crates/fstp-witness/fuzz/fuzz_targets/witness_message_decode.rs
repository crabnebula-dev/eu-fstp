//! Fuzz target `witness_message_decode` of `fstp-witness` (TH-26, H-05,
//! I-24, R-CR-03, M3 design section 15).
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
//! - the anchor of a decoded prepare is checked before any use. Under a
//!   fixed composite anchor key that nobody can sign for, the check
//!   refuses for real and never panics. Lane W2g landed the check. A
//!   refusal that still names the old composite encoding acceptance is
//!   a stub, and the target stops on it.

#![no_main]

use std::sync::OnceLock;

use fstp_witness::receipt::check_anchor_signature;
use fstp_witness::{
    ChainWitness, Refusal, Sender, WitnessMessage, decode_witness_message, encode_witness_message,
};
use libfuzzer_sys::fuzz_target;

/// The text of the old interim refusal (ADR-010 "Composite encoding").
const ACCEPTANCE: &str = "ADR-010 composite encoding acceptance (Daniel)";

/// The draft 19 composite public key length (ADR-010, row "Public key").
const PUBLIC_KEY_LEN: usize = 1952 + 32;

/// An anchor key history of one fixed composite public key whose private
/// key nobody holds: bytes from a multiplicative hash of their offset.
/// Its ML-DSA-65 half is not degenerate, so the key decodes and the
/// check reaches both halves.
fn history() -> &'static [Vec<u8>] {
    static KEYS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let key = (0..PUBLIC_KEY_LEN)
            .map(|i| {
                let x = u32::try_from(i).unwrap_or(0).wrapping_mul(2_654_435_761);
                x.to_be_bytes()[0]
            })
            .collect();
        vec![key]
    })
}

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
        WitnessMessage::Prepare(p) => {
            let got = check_anchor_signature(&p.anchor, history());
            match got {
                Ok(()) => panic!("an anchor signature the input made verified"),
                Err(e) => assert!(
                    !format!("{e:?}").contains(ACCEPTANCE),
                    "the anchor check is still a stub: {e:?}"
                ),
            }
        }
    }
});
