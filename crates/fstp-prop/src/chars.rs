//! Mapping between choices and characters.
//!
//! Choice 0 is the simplest character. ASCII comes first in a readable order:
//! lowercase, uppercase, digits, space, punctuation, then whitespace and control
//! characters. Code points from U+0080 follow in increasing order, skipping the
//! surrogate range.

use crate::rng::Rng;

/// ASCII in shrink order. Index 0 is the simplest character.
pub(crate) const ASCII_ORDER: &[u8; 128] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n\t\r\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f";

/// Number of ASCII choices that are letters, digits or space.
const ASCII_PLAIN: u64 = 63;

/// Largest ASCII choice.
pub(crate) const ASCII_MAX_CHOICE: u64 = 127;

/// Largest scalar-value choice: there are 0x110000 code points minus 0x800 surrogates.
pub(crate) const SCALAR_MAX_CHOICE: u64 = 0x10F7FF;

/// Largest choice that maps into the Basic Multilingual Plane.
const BMP_MAX_CHOICE: u64 = 0xF7FF;

const SURROGATE_START: u64 = 0xD800;
const SURROGATE_LEN: u64 = 0x800;

/// ASCII characters that often expose escaping, framing or parsing bugs.
const ASCII_SPECIAL: &[u8] = b"\x00\t\n\r \"'\\/<>&%;:,.=?#@`\x7f";

/// Unicode scalar values that often expose encoding and normalisation bugs.
const UNICODE_SPECIAL: &[char] = &[
    '\u{0}',
    '\u{7F}',
    '\u{80}',
    '\u{85}',
    '\u{A0}',
    '\u{AD}',
    '\u{E9}',
    '\u{DF}',
    '\u{130}',
    '\u{131}',
    '\u{301}',
    '\u{7FF}',
    '\u{800}',
    '\u{200B}',
    '\u{200D}',
    '\u{2028}',
    '\u{2029}',
    '\u{202E}',
    '\u{20AC}',
    '\u{D7FF}',
    '\u{E000}',
    '\u{FEFF}',
    '\u{FFFD}',
    '\u{FFFE}',
    '\u{FFFF}',
    '\u{10000}',
    '\u{1F600}',
    '\u{10FFFF}',
];

/// Returns the ASCII character for a choice in `0..=127`.
pub(crate) fn ascii_from_choice(c: u64) -> char {
    usize::try_from(c)
        .ok()
        .and_then(|i| ASCII_ORDER.get(i))
        .map_or('a', |&b| char::from(b))
}

/// Returns the choice for an ASCII byte, or 0 for a non-ASCII byte.
pub(crate) fn choice_for_ascii(b: u8) -> u64 {
    ASCII_ORDER
        .iter()
        .position(|&x| x == b)
        .and_then(|i| u64::try_from(i).ok())
        .unwrap_or(0)
}

/// Returns the Unicode scalar value for a choice in `0..=SCALAR_MAX_CHOICE`.
pub(crate) fn scalar_from_choice(c: u64) -> char {
    if c <= ASCII_MAX_CHOICE {
        return ascii_from_choice(c);
    }
    let cp = if c < SURROGATE_START {
        c
    } else {
        c.saturating_add(SURROGATE_LEN)
    };
    u32::try_from(cp)
        .ok()
        .and_then(char::from_u32)
        .unwrap_or('\u{FFFD}')
}

/// Returns the choice that maps to `ch`.
pub(crate) fn choice_for_scalar(ch: char) -> u64 {
    let cp = u64::from(u32::from(ch));
    if cp <= ASCII_MAX_CHOICE {
        u8::try_from(cp).map_or(0, choice_for_ascii)
    } else if cp < SURROGATE_START {
        cp
    } else {
        cp.saturating_sub(SURROGATE_LEN)
    }
}

/// Picks an edge-biased ASCII choice.
pub(crate) fn random_ascii_choice(rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 | 1 => rng.below(ASCII_PLAIN),
        2 => rng.upto(ASCII_MAX_CHOICE),
        _ => {
            let i = rng.index(ASCII_SPECIAL.len());
            ASCII_SPECIAL.get(i).map_or(0, |&b| choice_for_ascii(b))
        }
    }
}

/// Picks an edge-biased scalar-value choice.
pub(crate) fn random_scalar_choice(rng: &mut Rng) -> u64 {
    match rng.below(8) {
        0..=3 => random_ascii_choice(rng),
        4 | 5 => {
            let i = rng.index(UNICODE_SPECIAL.len());
            UNICODE_SPECIAL.get(i).map_or(0, |&c| choice_for_scalar(c))
        }
        6 => rng.upto(BMP_MAX_CHOICE),
        _ => rng.upto(SCALAR_MAX_CHOICE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_order_is_a_permutation() {
        let mut seen = [false; 128];
        for &b in ASCII_ORDER {
            assert!(b < 128);
            assert!(!seen[usize::from(b)], "duplicate {b}");
            seen[usize::from(b)] = true;
        }
        assert!(seen.iter().all(|&s| s));
        assert_eq!(ascii_from_choice(0), 'a');
        assert_eq!(ascii_from_choice(ASCII_PLAIN - 1), ' ');
    }

    #[test]
    fn scalar_mapping_round_trips() {
        for c in (0..=SCALAR_MAX_CHOICE).step_by(97).chain([
            0,
            127,
            128,
            0xD7FF,
            0xD800,
            BMP_MAX_CHOICE,
            SCALAR_MAX_CHOICE,
        ]) {
            let ch = scalar_from_choice(c);
            assert_eq!(choice_for_scalar(ch), c, "choice {c:#x} char {ch:?}");
        }
        for &ch in UNICODE_SPECIAL {
            assert_eq!(scalar_from_choice(choice_for_scalar(ch)), ch);
        }
        assert_eq!(scalar_from_choice(SCALAR_MAX_CHOICE), '\u{10FFFF}');
        assert_eq!(scalar_from_choice(BMP_MAX_CHOICE), '\u{FFFF}');
    }

    #[test]
    fn random_choices_stay_in_range() {
        let mut r = Rng::new(3);
        for _ in 0..10_000 {
            assert!(random_ascii_choice(&mut r) <= ASCII_MAX_CHOICE);
            assert!(random_scalar_choice(&mut r) <= SCALAR_MAX_CHOICE);
        }
    }
}
