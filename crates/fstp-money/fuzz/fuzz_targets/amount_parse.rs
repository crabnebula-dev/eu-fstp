//! Fuzz target for the ADR-006 amount parser (TH-26, H-05).
//!
//! Checks, for any UTF-8 input:
//! - parsing never panics, and error offsets stay inside the input;
//! - every accepted text matches the byte-level EUR grammar below, which is
//!   written separately from the parser;
//! - every accepted text round-trips byte for byte through `Display`;
//! - checked arithmetic and comparisons on parsed values never panic.
//!
//! W0 stub: the parser rejects everything, so only the accept direction is
//! asserted. Lane W1a also asserts that every grammar match is accepted,
//! in the commit that replaces the parser stub.

#![no_main]

use fstp_money::{Amount, Currency, NonNegAmount, PosAmount, checked_sum};
use libfuzzer_sys::fuzz_target;

/// The EUR grammar `-?(0|[1-9][0-9]*)\.[0-9]{2}`, excluding `-0.00`, with at
/// most 18 digits in all, which `Amount::MAX_ABS_MINOR` allows.
fn eur_grammar(text: &[u8]) -> bool {
    let (negative, rest) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, text),
    };
    let Some(dot) = rest.iter().position(|&b| b == b'.') else {
        return false;
    };
    let (int, frac) = rest.split_at(dot);
    let frac = &frac[1..];
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    let int_ok = match int {
        [b'0'] => true,
        [first, ..] => (b'1'..=b'9').contains(first) && digits(int),
        [] => false,
    };
    let frac_ok = frac.len() == 2 && digits(frac);
    let in_range = int.len() + frac.len() <= 18;
    let negative_zero = negative && int == b"0" && frac == b"00";
    int_ok && frac_ok && in_range && !negative_zero
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match Amount::parse(text, Currency::Eur) {
        Ok(a) => {
            assert!(eur_grammar(data), "accepted a non-canonical spelling");
            assert_eq!(a.to_string(), text, "accepted text does not round-trip");
            assert_eq!(a.currency(), Currency::Eur);
            assert!(a.minor().unsigned_abs() <= Amount::MAX_ABS_MINOR.unsigned_abs());
            let _ = a.checked_add(a);
            let _ = a.checked_sub(a.neg());
            let _ = a.cmp_same(a.neg());
            let _ = checked_sum(Currency::Eur, [a, a, a.neg()]);
            let _ = NonNegAmount::new(a);
            let _ = PosAmount::new(a);
        }
        Err(e) => {
            assert!(e.offset <= data.len(), "error offset outside the input");
            let _ = e.to_string();
        }
    }
});
