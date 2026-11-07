//! Fuzz target `vocab_parse` of `fstp-journey` (ADR-015, I-72, ADR-003).
//!
//! It feeds arbitrary bytes to the vocabulary pack parser. No input may
//! panic, and the result must be the same twice. An accepted pack must
//! keep the parser's promises: every key is an interface label, fixed
//! wording is unchanged, a plain pack names every label, and encoding the
//! pack and parsing it again gives an equal pack.

#![no_main]

use fstp_journey::vocab::{FIXED, LABEL_KEYS, MAX_LABEL_BYTES, PackKind, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse(data);
    assert_eq!(first, parse(data), "parse is not deterministic");
    let pack = match first {
        Ok(pack) => pack,
        Err(e) => {
            assert!(!e.to_string().is_empty(), "empty error text");
            return;
        }
    };
    for (key, text) in pack.labels() {
        assert!(LABEL_KEYS.contains(&key), "I-72: a key outside the list");
        assert!(
            !text.is_empty() && text.len() <= MAX_LABEL_BYTES,
            "text length"
        );
        assert!(
            !text.contains(['{', '}', '<', '>']),
            "placeholder or markup"
        );
        if let Some(f) = FIXED.iter().find(|f| f.key == key) {
            let want = match pack.kind() {
                PackKind::Plain => f.plain,
                PackKind::Voyage => f.voyage,
            };
            assert_eq!(text, want, "fixed wording changed");
        }
    }
    if pack.kind() == PackKind::Plain {
        for key in LABEL_KEYS {
            assert!(pack.get(key).is_some(), "plain pack lacks a label");
        }
    }
    let again = parse(pack.encode().as_bytes());
    assert_eq!(again.as_ref(), Ok(&pack), "round trip");
});
