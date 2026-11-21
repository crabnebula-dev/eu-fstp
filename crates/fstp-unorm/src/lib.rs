//! In-house Unicode normalisation and case folding (ADR-029).
//!
//! The forms follow UAX #15 and chapter 3 of the Unicode Standard, with
//! the tables of one pinned version of the Unicode Character Database
//! ([`UNICODE_VERSION`]):
//!
//! - [`nfd`]: canonical decomposition, then canonical ordering.
//! - [`nfc`]: [`nfd`], then canonical composition.
//! - [`casefold`]: full case folding, status C and F of `CaseFolding.txt`,
//!   the same for every language.
//! - [`fold_nfc`]: `NFC(casefold(NFD(s)))`, the match key of a name.
//!
//! [`fold_nfc`] is the standard canonical caseless match key
//! `NFD(casefold(NFD(s)))` (Unicode chapter 3.13, D145) composed to NFC.
//! NFC and NFD each give one string per canonical equivalence class, so
//! two strings have equal `fold_nfc` exactly when they match caselessly.
//! The tests prove that `fold_nfc` is idempotent and that its result is
//! in NFC.
//!
//! Every function takes any `&str`, never panics, and returns at most
//! [`MAX_EXPANSION`] times the input length in UTF-8 bytes. The crate has
//! no dependency and does no I/O. The tables in `tables.rs` are generated
//! by `tools/unorm-gen` from `third_party/unicode/<version>/`.

mod tables;

/// The Unicode version of the tables, as `(major, minor, update)`.
pub const UNICODE_VERSION: (u8, u8, u8) = tables::VERSION;

/// The largest factor by which [`nfd`], [`nfc`], [`casefold`] and
/// [`fold_nfc`] lengthen a string, in UTF-8 bytes. The test
/// `adr029_expansion_bound_holds_for_every_code_point` proves it over
/// every code point.
pub const MAX_EXPANSION: usize = 3;

/// The mask of one packed code point in the tables.
const CP: u64 = 0x1F_FFFF;

/// Hangul syllable constants (Unicode chapter 3.12).
const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

/// The deepest chain of one-level canonical decompositions. The test
/// `adr029_tables_are_sound` proves every chain shorter.
const MAX_DEPTH: u8 = 8;

/// A code point of a packed table entry.
fn unpack(e: u64, shift: u32) -> u32 {
    u32::try_from(e.checked_shr(shift).unwrap_or(0) & CP).unwrap_or(0)
}

/// The canonical combining class of `c`.
#[must_use]
pub fn combining_class(c: char) -> u8 {
    let cp = u64::from(u32::from(c));
    let i = tables::CCC.partition_point(|&e| e >> 29 <= cp);
    let Some(&e) = i.checked_sub(1).and_then(|j| tables::CCC.get(j)) else {
        return 0;
    };
    if cp <= (e >> 8) & CP {
        u8::try_from(e & 0xFF).unwrap_or(0)
    } else {
        0
    }
}

/// The one-level canonical decomposition of `c`: one or two characters.
fn canonical_pair(c: char) -> Option<(char, Option<char>)> {
    let cp = u64::from(u32::from(c));
    let i = tables::DECOMP
        .binary_search_by_key(&cp, |&e| e >> 42)
        .ok()?;
    let e = *tables::DECOMP.get(i)?;
    let a = char::from_u32(unpack(e, 21))?;
    let b = match unpack(e, 0) {
        0 => None,
        b => Some(char::from_u32(b)?),
    };
    Some((a, b))
}

/// The Hangul syllable decomposition of `c`, when `c` is a syllable.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "s < S_COUNT bounds every term far below u32::MAX"
)]
fn hangul_parts(c: char) -> Option<(u32, u32, Option<u32>)> {
    let s = u32::from(c).checked_sub(S_BASE).filter(|&s| s < S_COUNT)?;
    let l = L_BASE + s / N_COUNT;
    let v = V_BASE + (s % N_COUNT) / T_COUNT;
    let t = s % T_COUNT;
    Some((l, v, (t != 0).then_some(T_BASE + t)))
}

/// Appends the full canonical decomposition of `c` to `out`, with each
/// character's combining class.
fn push_decomposed(c: char, out: &mut Vec<(char, u8)>, depth: u8) {
    if let Some((l, v, t)) = hangul_parts(c) {
        for cp in [Some(l), Some(v), t].into_iter().flatten() {
            if let Some(ch) = char::from_u32(cp) {
                out.push((ch, 0));
            }
        }
        return;
    }
    match canonical_pair(c) {
        Some((a, b)) if depth < MAX_DEPTH => {
            let next = depth.saturating_add(1);
            push_decomposed(a, out, next);
            if let Some(b) = b {
                push_decomposed(b, out, next);
            }
        }
        _ => out.push((c, combining_class(c))),
    }
}

/// Sorts each run of non-starters by combining class. The sort is stable,
/// so characters of one class keep their order (Canonical Ordering
/// Algorithm).
fn canonical_order(buf: &mut [(char, u8)]) {
    for run in buf.split_mut(|&(_, cc)| cc == 0) {
        run.sort_by_key(|&(_, cc)| cc);
    }
}

/// The decomposed and ordered characters of `chars`.
fn decompose(chars: impl Iterator<Item = char>) -> Vec<(char, u8)> {
    let mut buf = Vec::new();
    for c in chars {
        push_decomposed(c, &mut buf, 0);
    }
    canonical_order(&mut buf);
    buf
}

/// The primary composite of `a` and `b`, if any.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "each term is bounded by the Hangul range checks before it"
)]
fn primary_composite(a: char, b: char) -> Option<char> {
    let (a32, b32) = (u32::from(a), u32::from(b));
    if let (Some(l), Some(v)) = (
        a32.checked_sub(L_BASE).filter(|&l| l < L_COUNT),
        b32.checked_sub(V_BASE).filter(|&v| v < V_COUNT),
    ) {
        return char::from_u32(S_BASE + (l * V_COUNT + v) * T_COUNT);
    }
    if let (Some(s), Some(t)) = (
        a32.checked_sub(S_BASE)
            .filter(|&s| s < S_COUNT && s % T_COUNT == 0),
        b32.checked_sub(T_BASE).filter(|&t| t > 0 && t < T_COUNT),
    ) {
        return char::from_u32(S_BASE + s + t);
    }
    let key = (u64::from(a32) << 21) | u64::from(b32);
    let i = tables::COMP.binary_search_by_key(&key, |&e| e >> 21).ok()?;
    char::from_u32(unpack(*tables::COMP.get(i)?, 0))
}

/// Canonical composition of a decomposed, ordered buffer (UAX #15,
/// Canonical Composition Algorithm).
fn compose(buf: Vec<(char, u8)>) -> String {
    let mut out: Vec<(char, u8)> = Vec::with_capacity(buf.len());
    let mut starter: Option<usize> = None;
    // The class of the last character kept since the starter, if any.
    let mut last: Option<u8> = None;
    for (c, cc) in buf {
        let blocked = last.is_some_and(|l| l == 0 || l >= cc);
        if !blocked
            && let Some(slot) = starter.and_then(|s| out.get_mut(s))
            && let Some(p) = primary_composite(slot.0, c)
        {
            slot.0 = p;
            continue;
        }
        if cc == 0 {
            starter = Some(out.len());
            last = None;
        } else {
            last = Some(cc);
        }
        out.push((c, cc));
    }
    out.into_iter().map(|(c, _)| c).collect()
}

/// The full case folding of `c` (status C and F), as one to three
/// characters, or `None` when `c` folds to itself.
fn fold_char(c: char) -> Option<[Option<char>; 3]> {
    let cp = u32::from(c);
    if let Ok(i) = tables::FOLD_MULTI.binary_search_by_key(&cp, |&(k, _)| k) {
        let (_, m) = tables::FOLD_MULTI.get(i)?;
        return Some(m.map(char::from_u32).map(|o| o.filter(|&c| c != '\0')));
    }
    let i = tables::FOLD
        .binary_search_by_key(&u64::from(cp), |&e| e >> 21)
        .ok()?;
    let f = char::from_u32(unpack(*tables::FOLD.get(i)?, 0))?;
    Some([Some(f), None, None])
}

/// Full case folding of a character sequence.
fn fold_chars(chars: impl Iterator<Item = char>) -> impl Iterator<Item = char> {
    chars
        .flat_map(|c| match fold_char(c) {
            Some(m) => m,
            None => [Some(c), None, None],
        })
        .flatten()
}

/// Canonical decomposition (NFD).
#[must_use]
pub fn nfd(s: &str) -> String {
    if s.is_ascii() {
        return s.to_owned();
    }
    decompose(s.chars()).into_iter().map(|(c, _)| c).collect()
}

/// Canonical decomposition followed by canonical composition (NFC).
#[must_use]
pub fn nfc(s: &str) -> String {
    if s.is_ascii() {
        return s.to_owned();
    }
    compose(decompose(s.chars()))
}

/// Full case folding (status C and F of `CaseFolding.txt`). It applies no
/// normalisation form, so its result need not be in NFC.
#[must_use]
pub fn casefold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    fold_chars(s.chars()).collect()
}

/// The match key `NFC(casefold(NFD(s)))`: two strings have equal keys
/// exactly when they are canonical caseless matches (Unicode chapter 3.13,
/// D145). The key is in NFC, and `fold_nfc(fold_nfc(s)) == fold_nfc(s)`.
#[must_use]
pub fn fold_nfc(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let folded = fold_chars(decompose(s.chars()).into_iter().map(|(c, _)| c));
    compose(decompose(folded))
}
