//! Fuzz target for the `FSTP_PROP_REPLAY` choice-sequence format (TH-26, H-05).
//!
//! Checks, for any input:
//! - parsing never panics and respects its limits;
//! - every accepted input is canonical: formatting the parsed sequence gives
//!   back the trimmed input byte for byte;
//! - any sequence, here built from the input bytes, round trips through
//!   format then parse.

#![no_main]

use fstp_prop::{ReplayLimits, format_replay, parse_replay_with};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ReplayLimits {
        max_input_len: 4096,
        max_choices: 256,
    };
    let unlimited = ReplayLimits {
        max_input_len: usize::MAX,
        max_choices: usize::MAX,
    };

    if let Ok(seq) = parse_replay_with(data, &limits) {
        assert!(seq.len() <= limits.max_choices);
        let text = format_replay(&seq);
        assert_eq!(
            text.as_bytes(),
            data.trim_ascii(),
            "accepted input is not canonical"
        );
        assert_eq!(
            parse_replay_with(text.as_bytes(), &limits).as_ref(),
            Ok(&seq)
        );
        // Looser limits never change an accepted result.
        assert_eq!(parse_replay_with(data, &unlimited).as_ref(), Ok(&seq));
    }

    let seq: Vec<u64> = data
        .chunks(8)
        .map(|chunk| {
            let mut word = [0u8; 8];
            for (dst, src) in word.iter_mut().zip(chunk) {
                *dst = *src;
            }
            u64::from_le_bytes(word)
        })
        .collect();
    let text = format_replay(&seq);
    assert_eq!(parse_replay_with(text.as_bytes(), &unlimited), Ok(seq));
});
