//! ADR-029, decided by Daniel on 2026-11-21: compatibility forms match.
//! Properties of NFKC, NFKD, `fold_nfkc` and `name_key`, and a comparison
//! of `fold_nfkc` with the `NFKC_CF` mapping of the vendored
//! `DerivedNormalizationProps.txt`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};
use fstp_unorm::{MAX_COMPAT_EXPANSION, casefold, fold_nfkc, name_key, nfc, nfd, nfkc, nfkd};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

/// Combining marks of several classes, and the Greek ypogegrammeni whose
/// folding is a starter.
const MARKS: [char; 7] = [
    '\u{0301}', '\u{0308}', '\u{0323}', '\u{031B}', '\u{0345}', '\u{0327}', '\u{05B0}',
];

/// Characters that stress compatibility decomposition, folding and the
/// removal of default ignorables.
const TRICKY: &[char] = &[
    'a',
    'A',
    'f',
    'i',
    'I',
    's',
    'S',
    ' ',
    '\u{00A0}',
    '\u{00A8}',
    '\u{00AD}',
    '\u{00B2}',
    '\u{00C5}',
    '\u{00DF}',
    '\u{00E9}',
    '\u{0130}',
    '\u{01C4}',
    '\u{01C5}',
    '\u{0345}',
    '\u{034F}',
    '\u{0390}',
    '\u{03A3}',
    '\u{03C2}',
    '\u{0587}',
    '\u{1E9B}',
    '\u{1E9E}',
    '\u{1FBC}',
    '\u{2000}',
    '\u{200B}',
    '\u{200D}',
    '\u{2126}',
    '\u{212A}',
    '\u{2163}',
    '\u{3000}',
    '\u{3164}',
    '\u{3300}',
    '\u{FB01}',
    '\u{FB2C}',
    '\u{FDFA}',
    '\u{FE18}',
    '\u{FF21}',
    '\u{FF41}',
    '\u{FFA0}',
    '\u{1D41A}',
    '\u{1D160}',
    '\u{1F130}',
    '\u{E0041}',
    '\u{AC00}',
    '\u{1100}',
    '\u{1161}',
    '\u{11A8}',
    '\u{0301}',
    '\u{0308}',
    '\u{0323}',
    '\u{031B}',
    '\u{0327}',
    '\u{0313}',
    '\u{0342}',
];

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

/// The `NFKC_CF` mappings of the vendored files.
fn nfkc_cf() -> &'static BTreeMap<u32, Vec<u32>> {
    static MAP: OnceLock<BTreeMap<u32, Vec<u32>>> = OnceLock::new();
    MAP.get_or_init(|| unorm_gen::load(&common::ucd_dir()).unwrap().nfkc_cf)
}

/// `toNFKC_Casefold(x)` as `DerivedNormalizationProps.txt` defines it for
/// strings: each character mapped by `NFKC_CF`, then NFC.
fn to_nfkc_casefold(x: &str) -> String {
    let map = nfkc_cf();
    let mapped: String = x
        .chars()
        .flat_map(|c| match map.get(&u32::from(c)) {
            Some(m) => common::text(m).chars().collect::<Vec<_>>(),
            None => vec![c],
        })
        .collect();
    nfc(&mapped)
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

/// Code points that neither decompose, fold nor compose: the unified
/// ideographs, private use and the unassigned planes.
fn plain(c: char) -> bool {
    matches!(
        u32::from(c),
        0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xE000..=0xF8FF
            | 0x2_0000..=0x2_F7FF
            | 0x2_FA20..=0xD_FFFF
            | 0xF_0000..
    )
}

/// ADR-029 "Match key": for every code point, `fold_nfkc` equals the
/// `NFKC_CF` mapping of `DerivedNormalizationProps.txt`, followed by NFC.
#[test]
fn adr029_fold_nfkc_equals_nfkc_cf_for_every_code_point() {
    let mut bad = Vec::new();
    for c in common::every_char() {
        let s = c.to_string();
        if fold_nfkc(&s) != to_nfkc_casefold(&s) {
            bad.push(u32::from(c));
        }
    }
    assert!(
        bad.is_empty(),
        "{} code points differ: {:X?}",
        bad.len(),
        &bad[..bad.len().min(10)]
    );
}

/// ADR-029 "Match key": for any string, `fold_nfkc(s)` equals
/// `toNFKC_Casefold(NFD(s))` computed from `DerivedNormalizationProps.txt`.
#[test]
fn adr029_fold_nfkc_equals_nfkc_cf_on_random_strings() {
    check("adr029_fold_nfkc_equals_nfkc_cf_on_random_strings", |g| {
        let s = tricky_string(g);
        g.note("s", &s);
        prop_assert_eq!(fold_nfkc(&s), to_nfkc_casefold(&nfd(&s)));
        Ok(())
    });
}

/// ADR-029 "Stability": `fold_nfkc` and `name_key` are idempotent and in
/// NFC, for every code point alone and before or after each mark of
/// `MARKS` (marks skipped for the plain code points, to keep the test fast).
#[test]
fn adr029_fold_nfkc_and_name_key_are_idempotent_for_every_code_point() {
    let mut bad = Vec::new();
    for c in common::every_char() {
        let mut inputs = vec![c.to_string()];
        for m in MARKS.iter().filter(|_| !plain(c)) {
            inputs.push(format!("{c}{m}"));
            inputs.push(format!("{m}{c}"));
        }
        for s in inputs {
            let k = fold_nfkc(&s);
            let n = name_key(&s);
            if fold_nfkc(&k) != k || nfc(&k) != k || name_key(&n) != n || nfc(&n) != n {
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

/// ADR-029 "Expansion bound": per code point, NFKD, NFKC, and every round
/// of `fold_nfkc` before its removals grow at most `MAX_COMPAT_EXPANSION`
/// times in UTF-8 bytes. Each round is a concatenation of per-character
/// results, reordered, and removal and composition never lengthen, so the
/// bound holds for every string.
#[test]
fn adr029_compat_expansion_bound_holds_for_every_code_point() {
    let mut worst = 0usize;
    for c in common::every_char() {
        let s = c.to_string();
        let n = s.len();
        let mut longest = nfkc(&s).len().max(nfkd(&s).len());
        let mut x = nfkd(&s);
        for _ in 0..4 {
            x = nfkd(&casefold(&x));
            longest = longest.max(x.len());
        }
        longest = longest.max(fold_nfkc(&s).len()).max(name_key(&s).len());
        assert!(
            longest <= MAX_COMPAT_EXPANSION * n,
            "U+{:04X} grows to {longest} bytes",
            u32::from(c)
        );
        worst = worst.max(longest.div_ceil(n));
    }
    assert_eq!(
        worst, MAX_COMPAT_EXPANSION,
        "MAX_COMPAT_EXPANSION is not tight"
    );
}

/// ADR-029: NFKC and NFKD are idempotent, agree with each other and with
/// the canonical forms, `fold_nfkc` is in NFC and the same for every
/// canonically equivalent spelling, and every result keeps the bound. Any
/// string, so none panics.
#[test]
fn adr029_compat_forms_are_stable_on_random_strings() {
    check("adr029_compat_forms_are_stable_on_random_strings", |g| {
        let s = tricky_string(g);
        g.note("s", &s);
        let (kc, kd, k) = (nfkc(&s), nfkd(&s), fold_nfkc(&s));
        prop_assert_eq!(nfkc(&kc), kc.clone());
        prop_assert_eq!(nfkd(&kd), kd.clone());
        prop_assert_eq!(nfc(&kd), kc.clone());
        prop_assert_eq!(nfkd(&kc), kd.clone());
        prop_assert_eq!(nfkc(&nfd(&s)), kc.clone());
        prop_assert_eq!(nfkc(&nfc(&s)), kc.clone());
        prop_assert_eq!(fold_nfkc(&k), k.clone());
        prop_assert_eq!(nfc(&k), k.clone());
        prop_assert_eq!(fold_nfkc(&nfc(&s)), k.clone());
        prop_assert_eq!(fold_nfkc(&nfd(&s)), k.clone());
        prop_assert_eq!(fold_nfkc(&kc), k.clone());
        for out in [&kc, &kd, &k] {
            prop_assert!(
                out.len() <= MAX_COMPAT_EXPANSION * s.len(),
                "{out:?} too long"
            );
        }
        Ok(())
    });
}

/// ADR-029 "Wiring": `name_key` has the shape of a tuple name. It has no
/// leading or trailing white space, its only white space is single
/// spaces, it is idempotent, and it is the same for every canonically
/// equivalent spelling.
#[test]
fn adr029_name_key_has_the_tuple_shape() {
    check("adr029_name_key_has_the_tuple_shape", |g| {
        let s = tricky_string(g);
        g.note("s", &s);
        let n = name_key(&s);
        prop_assert!(
            !n.starts_with(' ') && !n.ends_with(' '),
            "{n:?} not trimmed"
        );
        prop_assert!(!n.contains("  "), "{n:?} has a double space");
        prop_assert!(n.chars().all(|c| c == ' ' || !c.is_whitespace()), "{n:?}");
        prop_assert_eq!(name_key(&n), n.clone());
        prop_assert_eq!(name_key(&nfd(&s)), n.clone());
        prop_assert_eq!(name_key(&nfc(&s)), n.clone());
        Ok(())
    });
}

/// Spellings of one name part that differ by case, canonical
/// equivalence, compatibility variants or default ignorables.
const VARIANTS: &[&[&str]] = &[
    &["fi", "\u{FB01}", "FI", "Fi", "\u{FF46}\u{FF49}"],
    &["a", "A", "\u{FF21}", "\u{FF41}", "\u{1D41A}", "\u{1D400}"],
    &["iv", "IV", "\u{2163}", "\u{2173}", "I\u{200B}V"],
    &["2", "\u{00B2}", "\u{2082}", "\u{FF12}"],
    &[
        "marie",
        "MARIE",
        "ma\u{00AD}rie",
        "Ma\u{200D}rie",
        "M\u{034F}arie",
    ],
    &["ss", "\u{00DF}", "\u{1E9E}", "SS", "\u{017F}s"],
    &[
        "\u{00E9}",
        "\u{00C9}",
        "e\u{0301}",
        "E\u{0301}",
        "\u{FF25}\u{0301}",
    ],
    &[
        "\u{01C6}",
        "\u{01C5}",
        "\u{01C4}",
        "d\u{017E}",
        "D\u{017D}",
        "dz\u{030C}",
    ],
    &["\u{D55C}", "\u{1112}\u{1161}\u{11AB}"],
    &[" ", "\u{00A0}", "\u{3000}", "\u{2002}", "  ", " \u{00AD} "],
];

/// ADR-029, decided by Daniel on 2026-11-21: names that differ only by
/// case, canonical equivalence, compatibility variants, default
/// ignorables or white space have one `name_key`, and names that differ by
/// a part keep different keys.
#[test]
fn adr029_compatibility_variants_share_a_name_key() {
    check("adr029_compatibility_variants_share_a_name_key", |g| {
        let parts = g.vec(1..=8, |g| g.usize_in(0..=VARIANTS.len() - 1));
        let spell =
            |g: &mut Gen| -> String { parts.iter().map(|&p| *g.pick(VARIANTS[p])).collect() };
        let (a, b) = (spell(g), spell(g));
        g.note("pair", &(&a, &b));
        prop_assert_eq!(name_key(&a), name_key(&b));
        let at = g.usize_in(0..=parts.len() - 1);
        let other = (parts[at] + 1 + g.usize_in(0..=VARIANTS.len() - 2)) % VARIANTS.len();
        let mut changed = parts.clone();
        changed[at] = other;
        let c: String = changed.iter().map(|&p| VARIANTS[p][0]).collect();
        g.note("other", &c);
        prop_assert!(name_key(&a) != name_key(&c), "{a:?} and {c:?} share a key");
        Ok(())
    });
}
