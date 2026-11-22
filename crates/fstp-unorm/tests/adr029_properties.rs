//! ADR-029 "Stability" and "Expansion bound": properties of the forms,
//! exhaustive over every code point where that is cheap, and random over
//! strings built from the characters that stress normalisation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};
use fstp_unorm::{MAX_EXPANSION, casefold, fold_nfc, nfc, nfd};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

/// Combining marks of several classes, and the Greek ypogegrammeni whose
/// folding is a starter.
const MARKS: [char; 7] = [
    '\u{0301}', '\u{0308}', '\u{0323}', '\u{031B}', '\u{0345}', '\u{0327}', '\u{05B0}',
];

/// Characters that stress decomposition, ordering, composition and
/// folding.
const TRICKY: &[char] = &[
    'a',
    'A',
    'e',
    'E',
    'i',
    'I',
    'k',
    's',
    'S',
    ' ',
    '\u{00C5}',
    '\u{00DF}',
    '\u{00E9}',
    '\u{0130}',
    '\u{0131}',
    '\u{01C4}',
    '\u{01C5}',
    '\u{0344}',
    '\u{0390}',
    '\u{03A3}',
    '\u{03C2}',
    '\u{0587}',
    '\u{0958}',
    '\u{0B47}',
    '\u{0B3E}',
    '\u{0F73}',
    '\u{1100}',
    '\u{1161}',
    '\u{11A8}',
    '\u{AC00}',
    '\u{D55C}',
    '\u{1E9B}',
    '\u{1E9E}',
    '\u{1F80}',
    '\u{1F88}',
    '\u{1FB3}',
    '\u{1FBC}',
    '\u{2126}',
    '\u{212A}',
    '\u{212B}',
    '\u{FB03}',
    '\u{FB2C}',
    '\u{1D160}',
    '\u{11099}',
    '\u{110BA}',
    '\u{0301}',
    '\u{0308}',
    '\u{0323}',
    '\u{031B}',
    '\u{0345}',
    '\u{0327}',
    '\u{05B0}',
    '\u{0300}',
    '\u{0313}',
    '\u{0342}',
];

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

/// A string of tricky and arbitrary characters.
fn tricky_string(g: &mut Gen) -> String {
    let n = g.usize_in(0..=24);
    (0..n)
        .map(|_| {
            if g.u8_in(0..=3) == 0 {
                g.char()
            } else {
                *g.pick(TRICKY)
            }
        })
        .collect()
}

/// ADR-029 "Stability": `fold_nfc` is idempotent and its result is in NFC,
/// for every code point alone, and before or after each mark of `MARKS`.
/// The marks are skipped for the unified ideographs, private use and
/// unassigned planes, whose code points neither decompose, fold nor
/// compose, to keep the test fast.
#[test]
fn adr029_fold_nfc_is_idempotent_and_in_nfc_for_every_code_point() {
    let mut bad = Vec::new();
    for c in common::every_char() {
        let mut inputs = vec![c.to_string()];
        let plain = matches!(
            u32::from(c),
            0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xE000..=0xF8FF | 0x2_0000..=0x2_F7FF | 0x2_FA20..=0xD_FFFF | 0xF_0000..
        );
        for m in MARKS.iter().filter(|_| !plain) {
            inputs.push(format!("{c}{m}"));
            inputs.push(format!("{m}{c}"));
        }
        for s in inputs {
            let k = fold_nfc(&s);
            if fold_nfc(&k) != k || nfc(&k) != k {
                bad.push(s);
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} unstable inputs, first {:?}",
        bad.len(),
        &bad[..bad.len().min(5)]
    );
}

/// ADR-029 "Expansion bound": per code point, NFD, NFC, case folding and
/// the decomposed fold `NFD(casefold(NFD(c)))` grow at most
/// `MAX_EXPANSION` times in UTF-8 bytes. Each of those is a concatenation
/// of per-character results, reordered, and composition never lengthens
/// (`adr029_tables_are_sound`), so the bound holds for every string.
#[test]
fn adr029_expansion_bound_holds_for_every_code_point() {
    let mut worst = 0usize;
    for c in common::every_char() {
        let s = c.to_string();
        let n = s.len();
        let longest = [
            nfd(&s).len(),
            nfc(&s).len(),
            casefold(&s).len(),
            nfd(&casefold(&nfd(&s))).len(),
            fold_nfc(&s).len(),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(
            longest <= MAX_EXPANSION * n,
            "U+{:04X} grows to {longest} bytes",
            u32::from(c)
        );
        worst = worst.max(longest.div_ceil(n));
    }
    assert_eq!(worst, MAX_EXPANSION, "MAX_EXPANSION is not tight");
}

/// ADR-029 "Wiring": `fold_nfc` maps no character that is not white space
/// to white space, so collapsing white space before or after it gives one
/// tuple name.
#[test]
fn adr029_fold_nfc_makes_no_white_space() {
    for c in common::every_char().filter(|c| !c.is_whitespace()) {
        let k = fold_nfc(&c.to_string());
        assert!(
            !k.chars().any(char::is_whitespace),
            "U+{:04X}",
            u32::from(c)
        );
    }
}

/// ADR-029: the forms are idempotent, NFC and NFD agree on canonical
/// equivalence, `fold_nfc` is in NFC, case folding is idempotent, and every
/// result keeps the expansion bound. Any string, so none panics.
#[test]
fn adr029_forms_are_stable_on_random_strings() {
    check("adr029_forms_are_stable_on_random_strings", |g| {
        let s = tricky_string(g);
        g.note("s", &s);
        let (c, d, k) = (nfc(&s), nfd(&s), fold_nfc(&s));
        prop_assert_eq!(nfc(&c), c.clone());
        prop_assert_eq!(nfd(&d), d.clone());
        prop_assert_eq!(nfc(&d), c.clone());
        prop_assert_eq!(nfd(&c), d.clone());
        prop_assert_eq!(fold_nfc(&k), k.clone());
        prop_assert_eq!(nfc(&k), k.clone());
        prop_assert_eq!(fold_nfc(&c), k.clone());
        prop_assert_eq!(fold_nfc(&d), k.clone());
        prop_assert_eq!(casefold(&casefold(&s)), casefold(&s));
        for out in [&c, &d, &k] {
            prop_assert!(out.len() <= MAX_EXPANSION * s.len(), "{out:?} too long");
        }
        Ok(())
    });
}

/// Spellings of one letter that differ by case, by canonical
/// equivalence, or both, and so match caselessly.
const VARIANTS: &[&[&str]] = &[
    &["\u{00E9}", "\u{00C9}", "e\u{0301}", "E\u{0301}"],
    &["\u{00DF}", "ss", "SS", "Ss", "\u{1E9E}"],
    &["\u{01C6}", "\u{01C5}", "\u{01C4}"],
    &["\u{03C3}", "\u{03A3}", "\u{03C2}"],
    &["\u{00E5}", "\u{00C5}", "\u{212B}", "a\u{030A}", "A\u{030A}"],
    &["k", "K", "\u{212A}"],
    &["\u{03C9}", "\u{03A9}", "\u{2126}"],
    &[
        "\u{1FB3}",
        "\u{1FBC}",
        "\u{03B1}\u{0345}",
        "\u{03B1}\u{03B9}",
        "\u{0391}\u{0399}",
    ],
    &["\u{FB00}", "ff", "FF", "fF"],
    &["\u{D55C}", "\u{1112}\u{1161}\u{11AB}"],
    &[
        "\u{1EDB}",
        "\u{1EDA}",
        "o\u{031B}\u{0301}",
        "O\u{0301}\u{031B}",
        "\u{01A1}\u{0301}",
    ],
    &["m", "M"],
];

/// ADR-029 "Match key", Daniel's decision of 2026-11-21: names that
/// differ only by case or canonical equivalence have one `fold_nfc` key,
/// and names that differ by a letter keep different keys.
#[test]
fn adr029_fold_nfc_equates_case_and_canonical_variants() {
    check("adr029_fold_nfc_equates_case_and_canonical_variants", |g| {
        let letters = g.vec(1..=8, |g| g.usize_in(0..=VARIANTS.len() - 1));
        let spell =
            |g: &mut Gen| -> String { letters.iter().map(|&l| *g.pick(VARIANTS[l])).collect() };
        let (a, b) = (spell(g), spell(g));
        g.note("pair", &(&a, &b));
        prop_assert_eq!(fold_nfc(&a), fold_nfc(&b));
        // Replace one letter by another group: the key changes.
        let at = g.usize_in(0..=letters.len() - 1);
        let other = (letters[at] + 1 + g.usize_in(0..=VARIANTS.len() - 2)) % VARIANTS.len();
        let mut changed = letters.clone();
        changed[at] = other;
        let c: String = changed.iter().map(|&l| VARIANTS[l][0]).collect();
        g.note("other", &c);
        prop_assert!(fold_nfc(&a) != fold_nfc(&c), "{a:?} and {c:?} share a key");
        Ok(())
    });
}

/// ADR-029: the ASCII fast path agrees with the general path. An ASCII
/// prefix keeps its form when a non-ASCII starter follows it.
#[test]
fn adr029_ascii_fast_path_agrees() {
    check("adr029_ascii_fast_path_agrees", |g| {
        let s = g.ascii_string(0..=32);
        g.note("s", &s);
        let tail = "\u{00C9}";
        prop_assert_eq!(
            fold_nfc(&format!("{s}{tail}")),
            format!("{}\u{00E9}", fold_nfc(&s))
        );
        prop_assert_eq!(
            casefold(&format!("{s}{tail}")),
            format!("{}\u{00E9}", casefold(&s))
        );
        prop_assert_eq!(nfc(&format!("{s}{tail}")), format!("{}{tail}", nfc(&s)));
        prop_assert_eq!(nfd(&format!("{s}{tail}")), format!("{}E\u{0301}", nfd(&s)));
        prop_assert_eq!(fold_nfc(&s), s.to_ascii_lowercase());
        Ok(())
    });
}

/// ADR-029: a long run of combining marks is ordered in `n log n` time, so
/// a hostile name cannot stall the vault. 200,000 marks of mixed classes.
#[test]
fn adr029_long_mark_runs_stay_fast() {
    let s: String = std::iter::once('a')
        .chain((0..200_000).map(|i| MARKS[i % MARKS.len()]))
        .collect();
    let started = std::time::Instant::now();
    let k = fold_nfc(&s);
    assert!(k.len() <= MAX_EXPANSION * s.len());
    assert!(
        started.elapsed().as_secs() < 20,
        "took {:?}",
        started.elapsed()
    );
}
